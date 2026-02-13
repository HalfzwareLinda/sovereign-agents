#!/usr/bin/env node
/**
 * nip46-server.js — NIP-46 Nostr Connect signer (bunker)
 *
 * Holds the agent's nsec and signs events on request via Nostr Connect protocol.
 * Uses NDK's built-in NDKNip46Backend — no external nsecbunker package needed.
 *
 * Reads nsec from /opt/agent-keys/keys.json
 * Writes bunker:// connection string to /opt/agent-keys/bunker_connection.txt
 */

const fs = require("fs");
const NDKModule = require("@nostr-dev-kit/ndk");
const NDK = NDKModule.default || NDKModule.NDK;
const { NDKNip46Backend, NDKPrivateKeySigner } = NDKModule;

const KEYS_PATH = "/opt/agent-keys/keys.json";
const BUNKER_CONN_PATH = "/opt/agent-keys/bunker_connection.txt";
const RELAYS = [
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://nos.lol",
];

async function main() {
    const keys = JSON.parse(fs.readFileSync(KEYS_PATH, "utf-8"));
    const nsec = keys.nostr?.nsec;
    const pubkeyHex = keys.nostr?.public_key_hex;
    if (!nsec) {
        console.error("No nsec found in", KEYS_PATH);
        process.exit(1);
    }

    const ndk = new NDK({ explicitRelayUrls: RELAYS });
    await ndk.connect();
    console.log("Connected to relays:", RELAYS.join(", "));

    const signer = new NDKPrivateKeySigner(nsec);

    // NIP-46 backend — auto-approve all local requests
    const backend = new NDKNip46Backend(ndk, signer, () => true);
    await backend.start();

    const relayParams = RELAYS.map((r) => `relay=${encodeURIComponent(r)}`).join("&");
    const bunkerUrl = `bunker://${pubkeyHex}?${relayParams}`;

    fs.writeFileSync(BUNKER_CONN_PATH, bunkerUrl, "utf-8");
    fs.chmodSync(BUNKER_CONN_PATH, 0o600);
    console.log("NIP-46 bunker running");
    console.log("Connection string:", bunkerUrl);

    process.on("SIGTERM", () => {
        console.log("Shutting down NIP-46 bunker");
        process.exit(0);
    });
}

main().catch((err) => {
    console.error("NIP-46 server error:", err);
    process.exit(1);
});
