#!/usr/bin/env node
/**
 * nip46-server.js — NIP-46 Nostr Connect signer (bunker)
 *
 * Holds the agent's nsec and signs events on request via Nostr Connect protocol.
 * Uses NDK's built-in NDKNip46Backend — no external nsecbunker package needed.
 *
 * SECURITY: Only approves signing requests that include the correct shared
 * secret. The secret is generated at startup and written to the bunker
 * connection string. Only local processes that can read the connection
 * string file (/opt/agent-keys/bunker_connection.txt) can sign events.
 *
 * Reads nsec from /opt/agent-keys/nostr.json
 * Writes bunker:// connection string to /opt/agent-keys/bunker_connection.txt
 */

const fs = require("fs");
const crypto = require("crypto");
const NDKModule = require("@nostr-dev-kit/ndk");
const NDK = NDKModule.default || NDKModule.NDK;
const { NDKNip46Backend, NDKPrivateKeySigner } = NDKModule;

const KEYS_PATH = "/opt/agent-keys/nostr.json";
// Fallback to legacy combined keys.json if nostr.json doesn't exist
const KEYS_PATH_LEGACY = "/opt/agent-keys/keys.json";
const BUNKER_CONN_PATH = "/opt/agent-keys/bunker_connection.txt";
const RELAYS = [
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://nos.lol",
];

async function main() {
    // Load keys — try new separate file first, fall back to legacy combined file
    let keysPath = KEYS_PATH;
    if (!fs.existsSync(KEYS_PATH) && fs.existsSync(KEYS_PATH_LEGACY)) {
        keysPath = KEYS_PATH_LEGACY;
        console.log("Using legacy keys.json (consider migrating to separate key files)");
    }

    const keys = JSON.parse(fs.readFileSync(keysPath, "utf-8"));
    const nsec = keys.nostr?.nsec || keys.nsec;
    const pubkeyHex = keys.nostr?.public_key_hex || keys.public_key_hex;
    if (!nsec) {
        console.error("No nsec found in", keysPath);
        process.exit(1);
    }

    // Generate a shared secret for authenticating local NIP-46 clients
    const bunkerSecret = crypto.randomBytes(32).toString("hex");

    const ndk = new NDK({ explicitRelayUrls: RELAYS });
    await ndk.connect();
    console.log("Connected to relays:", RELAYS.join(", "));

    const signer = new NDKPrivateKeySigner(nsec);

    // NIP-46 backend — only approve requests that include the correct secret.
    // The secret is embedded in the bunker:// connection string, which is only
    // readable by root (mode 600). This prevents remote attackers from using
    // the bunker even if they know the agent's pubkey.
    const backend = new NDKNip46Backend(ndk, signer, (params) => {
        // NDKNip46Backend passes the connection params including the secret.
        // If the NDK version doesn't pass params, fall back to rejecting.
        if (!params) {
            console.warn("NIP-46 request rejected: no params (upgrade NDK for secret-based auth)");
            return false;
        }
        const requestSecret = typeof params === "string" ? params : params.secret;
        if (requestSecret === bunkerSecret) {
            return true;
        }
        console.warn("NIP-46 request rejected: invalid secret");
        return false;
    });
    await backend.start();

    const relayParams = RELAYS.map((r) => `relay=${encodeURIComponent(r)}`).join("&");
    const bunkerUrl = `bunker://${pubkeyHex}?${relayParams}&secret=${bunkerSecret}`;

    fs.writeFileSync(BUNKER_CONN_PATH, bunkerUrl, "utf-8");
    fs.chmodSync(BUNKER_CONN_PATH, 0o600);
    console.log("NIP-46 bunker running (secret-authenticated)");
    // Don't log the full connection string — it contains the secret
    console.log("Connection string written to:", BUNKER_CONN_PATH);

    process.on("SIGTERM", () => {
        console.log("Shutting down NIP-46 bunker");
        process.exit(0);
    });
}

main().catch((err) => {
    console.error("NIP-46 server error:", err);
    process.exit(1);
});
