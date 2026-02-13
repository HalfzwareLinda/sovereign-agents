#!/usr/bin/env node
/**
 * nwc_pay.js — Pay a Lightning invoice via Nostr Wallet Connect (NWC / NIP-47)
 *
 * Usage:
 *   NODE_PATH=/opt/agent-ndk/node_modules node nwc_pay.js <nwc_connection_string> <bolt11_invoice>
 *
 * Outputs JSON to stdout:
 *   {"success": true, "preimage": "...", "fees_paid": 0}
 *   {"success": false, "error": "..."}
 *
 * NWC flow:
 *   1. Parse connection string → wallet_pubkey, relay, secret (client privkey)
 *   2. Connect to relay
 *   3. Send kind 23194 request (NIP-04 encrypted pay_invoice)
 *   4. Subscribe for kind 23195 response
 *   5. Decrypt response, output result
 */

const crypto = require("crypto");

// NDK imports — handle both default and named exports
const NDKModule = require("@nostr-dev-kit/ndk");
const NDK = NDKModule.default || NDKModule.NDK;
const { NDKPrivateKeySigner, NDKEvent, NDKUser } = NDKModule;

const TIMEOUT_MS = 60000; // 60 seconds max wait for payment

function parseNwcString(nwcStr) {
    // Format: nostr+walletconnect://<wallet_pubkey>?relay=<url>&secret=<hex>&...
    const cleaned = nwcStr.replace("nostr+walletconnect://", "");
    const [pubkey, queryStr] = cleaned.split("?");
    const params = new URLSearchParams(queryStr);
    return {
        walletPubkey: pubkey,
        relay: decodeURIComponent(params.get("relay") || ""),
        secret: params.get("secret") || "",
        lud16: params.get("lud16") || "",
    };
}

// Bech32 encode for nsec
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function bech32Polymod(values) {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
        const b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i];
    }
    return chk;
}
function bech32HrpExpand(hrp) {
    const ret = [];
    for (const c of hrp) ret.push(c.charCodeAt(0) >> 5);
    ret.push(0);
    for (const c of hrp) ret.push(c.charCodeAt(0) & 31);
    return ret;
}
function convertBits(data, fromBits, toBits, pad) {
    let acc = 0, bits = 0, ret = [];
    const maxv = (1 << toBits) - 1;
    for (const v of data) {
        acc = (acc << fromBits) | v;
        bits += fromBits;
        while (bits >= toBits) { bits -= toBits; ret.push((acc >> bits) & maxv); }
    }
    if (pad && bits) ret.push((acc << (toBits - bits)) & maxv);
    return ret;
}
function bech32Encode(hrp, bytes) {
    const data5 = convertBits(bytes, 8, 5, true);
    const values = bech32HrpExpand(hrp).concat(data5).concat([0, 0, 0, 0, 0, 0]);
    const polymod = bech32Polymod(values) ^ 1;
    const checksum = Array.from({ length: 6 }, (_, i) => (polymod >> 5 * (5 - i)) & 31);
    return hrp + "1" + data5.concat(checksum).map((d) => CHARSET[d]).join("");
}

function hexToNsec(hex) {
    return bech32Encode("nsec", Array.from(Buffer.from(hex, "hex")));
}

// NIP-04 encryption (shared secret via ECDH + AES-256-CBC)
function nip04Encrypt(privkeyHex, pubkeyHex, plaintext) {
    const ecdh = crypto.createECDH("secp256k1");
    ecdh.setPrivateKey(Buffer.from(privkeyHex, "hex"));
    const sharedPoint = ecdh.computeSecret(Buffer.from("02" + pubkeyHex, "hex"));
    const sharedX = sharedPoint.subarray(0, 32);

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", sharedX, iv);
    let encrypted = cipher.update(plaintext, "utf8", "base64");
    encrypted += cipher.final("base64");
    return encrypted + "?iv=" + iv.toString("base64");
}

function nip04Decrypt(privkeyHex, pubkeyHex, ciphertext) {
    const [encData, ivPart] = ciphertext.split("?iv=");
    const ecdh = crypto.createECDH("secp256k1");
    ecdh.setPrivateKey(Buffer.from(privkeyHex, "hex"));
    const sharedPoint = ecdh.computeSecret(Buffer.from("02" + pubkeyHex, "hex"));
    const sharedX = sharedPoint.subarray(0, 32);

    const iv = Buffer.from(ivPart, "base64");
    const decipher = crypto.createDecipheriv("aes-256-cbc", sharedX, iv);
    let decrypted = decipher.update(encData, "base64", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
}

async function main() {
    const args = process.argv.slice(2);
    if (args.length < 2) {
        console.error("Usage: node nwc_pay.js <nwc_connection_string> <bolt11_invoice>");
        process.exit(1);
    }

    const nwcStr = args[0];
    const bolt11 = args[1];

    // Parse NWC connection
    const nwc = parseNwcString(nwcStr);
    if (!nwc.walletPubkey || !nwc.relay || !nwc.secret) {
        console.log(JSON.stringify({ success: false, error: "Invalid NWC connection string" }));
        process.exit(1);
    }

    const clientNsec = hexToNsec(nwc.secret);

    // Connect NDK to the wallet's relay
    const signer = new NDKPrivateKeySigner(clientNsec);
    const ndk = new NDK({ explicitRelayUrls: [nwc.relay], signer });
    await ndk.connect();

    // Wait for relay connection
    await new Promise((r) => setTimeout(r, 2000));

    // Get our pubkey
    const clientUser = await signer.user();
    const clientPubkey = clientUser.pubkey;

    // Build NIP-47 pay_invoice request
    const requestPayload = JSON.stringify({
        method: "pay_invoice",
        params: { invoice: bolt11 },
    });

    // NIP-04 encrypt the payload
    const encryptedContent = nip04Encrypt(nwc.secret, nwc.walletPubkey, requestPayload);

    // Create kind 23194 event
    const requestEvent = new NDKEvent(ndk);
    requestEvent.kind = 23194;
    requestEvent.content = encryptedContent;
    requestEvent.tags = [["p", nwc.walletPubkey]];
    await requestEvent.sign();

    // Subscribe for response (kind 23195) before publishing request
    const responsePromise = new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            reject(new Error("Timeout waiting for NWC response"));
        }, TIMEOUT_MS);

        const sub = ndk.subscribe(
            {
                kinds: [23195],
                authors: [nwc.walletPubkey],
                "#p": [clientPubkey],
                since: Math.floor(Date.now() / 1000) - 10,
            },
            { closeOnEose: false }
        );

        sub.on("event", (event) => {
            clearTimeout(timeout);
            try {
                const decrypted = nip04Decrypt(nwc.secret, nwc.walletPubkey, event.content);
                const response = JSON.parse(decrypted);
                resolve(response);
            } catch (err) {
                reject(new Error(`Failed to decrypt response: ${err.message}`));
            }
            sub.stop();
        });
    });

    // Publish request
    await requestEvent.publish();

    // Wait for response
    try {
        const response = await responsePromise;

        if (response.error) {
            console.log(JSON.stringify({
                success: false,
                error: response.error.message || JSON.stringify(response.error),
                code: response.error.code || null,
            }));
            process.exit(1);
        }

        const result = response.result || {};
        console.log(JSON.stringify({
            success: true,
            preimage: result.preimage || "",
            fees_paid: result.fees_paid || 0,
        }));
        process.exit(0);
    } catch (err) {
        console.log(JSON.stringify({ success: false, error: err.message }));
        process.exit(1);
    }
}

main().catch((err) => {
    console.log(JSON.stringify({ success: false, error: err.message }));
    process.exit(1);
});
