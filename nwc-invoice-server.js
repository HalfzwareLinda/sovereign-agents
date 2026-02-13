#!/usr/bin/env node
/**
 * nwc-invoice-server.js — NWC Lightning Invoice Service
 *
 * Creates Lightning invoices and checks payment status via Nostr Wallet Connect (NIP-47).
 * Connects to a remote wallet (e.g. Primal) over a WebSocket relay.
 *
 * Endpoints:
 *   POST /invoice/create     — create invoice { amount_sats, memo, order_number }
 *   GET  /invoice/status/:ph — check payment { paid, payment_hash, settled_at }
 *   GET  /health             — { status, nwc_connected }
 *
 * Environment:
 *   NWC_CONNECTION_STRING    — nostr+walletconnect://<pubkey>?relay=<url>&secret=<hex>
 *   NWC_AUTH_TOKEN           — bearer token for /invoice/create (default: dsc-prov-a7f3e2b1c9d4)
 *   NWC_PORT                 — listen port (default: 3001)
 */

const http = require("http");
const crypto = require("crypto");
const WebSocket = require("ws");

const PORT = parseInt(process.env.NWC_PORT || "3001", 10);
const AUTH_TOKEN = process.env.NWC_AUTH_TOKEN || "dsc-prov-a7f3e2b1c9d4";
const NWC_STRING = process.env.NWC_CONNECTION_STRING || "";

// =============================================================================
// NWC Connection String Parser
// =============================================================================

function parseNwcString(nwcStr) {
    const cleaned = nwcStr.replace("nostr+walletconnect://", "");
    const qIdx = cleaned.indexOf("?");
    const pubkey = cleaned.substring(0, qIdx);
    const params = new URLSearchParams(cleaned.substring(qIdx + 1));
    return {
        walletPubkey: pubkey,
        relay: decodeURIComponent(params.get("relay") || ""),
        secret: params.get("secret") || "",
    };
}

// =============================================================================
// Secp256k1 / Nostr Helpers (using Node.js native crypto)
// =============================================================================

function getPublicKeyHex(privkeyHex) {
    const ecdh = crypto.createECDH("secp256k1");
    ecdh.setPrivateKey(Buffer.from(privkeyHex, "hex"));
    return ecdh.getPublicKey("hex", "compressed").slice(2); // x-only
}

function sha256(data) {
    return crypto.createHash("sha256").update(data).digest();
}

// Schnorr signing (BIP-340) — simplified using Node.js crypto
// Node 19+ has native schnorr, but for compatibility we use a manual approach
function schnorrSign(privkeyHex, msgHash) {
    // Use the coincurve-style approach via ECDSA then adapt
    // Actually, Node.js crypto doesn't have native schnorr.
    // We'll use a deterministic nonce approach (RFC 6979-like)
    const privKey = Buffer.from(privkeyHex, "hex");
    const k = sha256(Buffer.concat([privKey, msgHash]));

    const ecdh = crypto.createECDH("secp256k1");
    ecdh.setPrivateKey(k);
    const R = ecdh.getPublicKey("hex", "compressed");
    const Rx = Buffer.from(R.slice(2), "hex");
    const Ry = parseInt(R.slice(0, 2), 16);

    const pubkey = Buffer.from(getPublicKeyHex(privkeyHex), "hex");
    const e = sha256(Buffer.concat([Rx, pubkey, msgHash]));

    // s = k + e * privKey (mod n)
    const n = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    let kBig = BigInt("0x" + k.toString("hex"));
    const eBig = BigInt("0x" + e.toString("hex"));
    const dBig = BigInt("0x" + privkeyHex);

    // If R.y is odd, negate k
    if (Ry === 0x03) {
        kBig = n - kBig;
    }

    const s = ((kBig + eBig * dBig) % n + n) % n;
    const sHex = s.toString(16).padStart(64, "0");
    return Rx.toString("hex") + sHex;
}

function serializeEvent(event) {
    return JSON.stringify([
        0,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags,
        event.content,
    ]);
}

function signEvent(privkeyHex, event) {
    const pubkey = getPublicKeyHex(privkeyHex);
    event.pubkey = pubkey;
    const serialized = serializeEvent(event);
    const id = sha256(Buffer.from(serialized)).toString("hex");
    event.id = id;
    event.sig = schnorrSign(privkeyHex, Buffer.from(id, "hex"));
    return event;
}

// =============================================================================
// NIP-04 Encryption/Decryption
// =============================================================================

function nip04Encrypt(privkeyHex, pubkeyHex, plaintext) {
    const ecdh = crypto.createECDH("secp256k1");
    ecdh.setPrivateKey(Buffer.from(privkeyHex, "hex"));
    const shared = ecdh.computeSecret(Buffer.from("02" + pubkeyHex, "hex"));
    const sharedX = shared.subarray(0, 32);

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", sharedX, iv);
    let enc = cipher.update(plaintext, "utf8", "base64");
    enc += cipher.final("base64");
    return enc + "?iv=" + iv.toString("base64");
}

function nip04Decrypt(privkeyHex, pubkeyHex, ciphertext) {
    const [encData, ivPart] = ciphertext.split("?iv=");
    const ecdh = crypto.createECDH("secp256k1");
    ecdh.setPrivateKey(Buffer.from(privkeyHex, "hex"));
    const shared = ecdh.computeSecret(Buffer.from("02" + pubkeyHex, "hex"));
    const sharedX = shared.subarray(0, 32);

    const iv = Buffer.from(ivPart, "base64");
    const decipher = crypto.createDecipheriv("aes-256-cbc", sharedX, iv);
    let dec = decipher.update(encData, "base64", "utf8");
    dec += decipher.final("utf8");
    return dec;
}

// =============================================================================
// NWC Client
// =============================================================================

class NwcClient {
    constructor(nwcString) {
        const parsed = parseNwcString(nwcString);
        this.walletPubkey = parsed.walletPubkey;
        this.relayUrl = parsed.relay;
        this.secret = parsed.secret;
        this.clientPubkey = getPublicKeyHex(this.secret);
        this.ws = null;
        this.connected = false;
        this.pendingRequests = new Map(); // id → {resolve, reject, timeout}
        this.reconnectTimer = null;
    }

    connect() {
        return new Promise((resolve, reject) => {
            if (!this.relayUrl) return reject(new Error("No relay URL"));

            console.log(`NWC: connecting to ${this.relayUrl}`);
            this.ws = new WebSocket(this.relayUrl);

            this.ws.on("open", () => {
                console.log("NWC: relay connected");
                this.connected = true;

                // Subscribe for response events (kind 23195) from wallet
                const subId = crypto.randomBytes(8).toString("hex");
                const filter = {
                    kinds: [23195],
                    authors: [this.walletPubkey],
                    "#p": [this.clientPubkey],
                    since: Math.floor(Date.now() / 1000) - 60,
                };
                this.ws.send(JSON.stringify(["REQ", subId, filter]));
                resolve();
            });

            this.ws.on("message", (data) => {
                try {
                    const msg = JSON.parse(data.toString());
                    if (msg[0] === "EVENT" && msg[2]) {
                        this._handleEvent(msg[2]);
                    }
                } catch (e) {
                    // ignore parse errors
                }
            });

            this.ws.on("close", () => {
                console.log("NWC: relay disconnected");
                this.connected = false;
                this._scheduleReconnect();
            });

            this.ws.on("error", (err) => {
                console.error("NWC: WebSocket error:", err.message);
                if (!this.connected) reject(err);
            });
        });
    }

    _scheduleReconnect() {
        if (this.reconnectTimer) return;
        this.reconnectTimer = setTimeout(() => {
            this.reconnectTimer = null;
            this.connect().catch((e) =>
                console.error("NWC: reconnect failed:", e.message)
            );
        }, 5000);
    }

    _handleEvent(event) {
        if (event.kind !== 23195) return;

        try {
            const decrypted = nip04Decrypt(
                this.secret,
                this.walletPubkey,
                event.content
            );
            const response = JSON.parse(decrypted);

            // Match to pending request via the 'e' tag (references request event id)
            const eTag = (event.tags || []).find((t) => t[0] === "e");
            const requestId = eTag ? eTag[1] : null;

            if (requestId && this.pendingRequests.has(requestId)) {
                const pending = this.pendingRequests.get(requestId);
                clearTimeout(pending.timeout);
                this.pendingRequests.delete(requestId);

                if (response.error) {
                    pending.reject(
                        new Error(response.error.message || JSON.stringify(response.error))
                    );
                } else {
                    pending.resolve(response.result || response);
                }
            }
        } catch (e) {
            console.error("NWC: failed to handle response:", e.message);
        }
    }

    async _sendRequest(method, params, timeoutMs = 30000) {
        if (!this.connected || !this.ws) {
            throw new Error("NWC not connected");
        }

        const payload = JSON.stringify({ method, params });
        const encrypted = nip04Encrypt(this.secret, this.walletPubkey, payload);

        const event = {
            kind: 23194,
            created_at: Math.floor(Date.now() / 1000),
            tags: [["p", this.walletPubkey]],
            content: encrypted,
        };
        const signed = signEvent(this.secret, event);

        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                this.pendingRequests.delete(signed.id);
                reject(new Error(`NWC request timed out (${method})`));
            }, timeoutMs);

            this.pendingRequests.set(signed.id, { resolve, reject, timeout });
            this.ws.send(JSON.stringify(["EVENT", signed]));
        });
    }

    async makeInvoice(amountMsats, description = "") {
        const result = await this._sendRequest("make_invoice", {
            amount: amountMsats,
            description,
        });
        return {
            bolt11: result.invoice || "",
            payment_hash: result.payment_hash || "",
            description: result.description || description,
            amount_msats: amountMsats,
        };
    }

    async lookupInvoice(paymentHash) {
        const result = await this._sendRequest("lookup_invoice", {
            payment_hash: paymentHash,
        });
        // Primal/NWC returns: { invoice, description, description_hash, preimage,
        //   payment_hash, amount, fees_paid, created_at, expires_at, settled_at, type }
        const settled = result.settled_at && result.settled_at > 0;
        return {
            paid: settled,
            payment_hash: result.payment_hash || paymentHash,
            settled_at: settled ? new Date(result.settled_at * 1000).toISOString() : null,
            amount_msats: result.amount || 0,
            bolt11: result.invoice || "",
        };
    }
}

// =============================================================================
// HTTP Server
// =============================================================================

let nwc = null;

function jsonResponse(res, status, data) {
    res.writeHead(status, {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
    });
    res.end(JSON.stringify(data));
}

function parseBody(req) {
    return new Promise((resolve, reject) => {
        let body = "";
        req.on("data", (c) => (body += c));
        req.on("end", () => {
            try {
                resolve(body ? JSON.parse(body) : {});
            } catch (e) {
                reject(new Error("Invalid JSON"));
            }
        });
    });
}

function authenticate(req) {
    const auth = req.headers.authorization || "";
    return auth === `Bearer ${AUTH_TOKEN}`;
}

const server = http.createServer(async (req, res) => {
    // CORS preflight
    if (req.method === "OPTIONS") {
        res.writeHead(204, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        });
        return res.end();
    }

    const url = new URL(req.url, `http://localhost:${PORT}`);

    // Health
    if (req.method === "GET" && url.pathname === "/health") {
        return jsonResponse(res, 200, {
            status: "ok",
            nwc_connected: nwc ? nwc.connected : false,
        });
    }

    // Create invoice
    if (req.method === "POST" && url.pathname === "/invoice/create") {
        if (!authenticate(req)) {
            return jsonResponse(res, 401, { error: "Unauthorized" });
        }
        if (!nwc || !nwc.connected) {
            return jsonResponse(res, 503, { error: "NWC not connected" });
        }

        try {
            const body = await parseBody(req);
            const amountSats = body.amount_sats;
            if (!amountSats || amountSats <= 0) {
                return jsonResponse(res, 400, { error: "amount_sats required (positive integer)" });
            }

            const memo = body.memo || body.order_number || "Agent provisioning";
            const amountMsats = Math.round(amountSats * 1000);

            console.log(`Creating invoice: ${amountSats} sats, memo: ${memo}`);
            const result = await nwc.makeInvoice(amountMsats, memo);

            return jsonResponse(res, 200, {
                bolt11: result.bolt11,
                payment_hash: result.payment_hash,
                amount_sats: amountSats,
                order_number: body.order_number || "",
            });
        } catch (err) {
            console.error("Invoice creation error:", err.message);
            return jsonResponse(res, 500, { error: err.message });
        }
    }

    // Check invoice status
    const statusMatch = url.pathname.match(/^\/invoice\/status\/([a-f0-9]+)$/i);
    if (req.method === "GET" && statusMatch) {
        if (!nwc || !nwc.connected) {
            return jsonResponse(res, 503, { error: "NWC not connected" });
        }

        const paymentHash = statusMatch[1];
        try {
            const result = await nwc.lookupInvoice(paymentHash);
            return jsonResponse(res, 200, result);
        } catch (err) {
            console.error("Invoice status error:", err.message);
            return jsonResponse(res, 500, { error: err.message });
        }
    }

    jsonResponse(res, 404, { error: "Not found" });
});

// =============================================================================
// Startup
// =============================================================================

async function main() {
    if (!NWC_STRING) {
        console.error("ERROR: NWC_CONNECTION_STRING environment variable not set");
        process.exit(1);
    }

    nwc = new NwcClient(NWC_STRING);

    try {
        await nwc.connect();
    } catch (err) {
        console.error("NWC initial connection failed:", err.message);
        console.log("Server will start anyway — NWC will reconnect");
    }

    server.listen(PORT, () => {
        console.log(`NWC Invoice Server listening on port ${PORT}`);
        console.log(`  Wallet: ${nwc.walletPubkey.substring(0, 16)}...`);
        console.log(`  Relay:  ${nwc.relayUrl}`);
        console.log(`  Client: ${nwc.clientPubkey.substring(0, 16)}...`);
    });
}

main().catch((err) => {
    console.error("Fatal:", err);
    process.exit(1);
});
