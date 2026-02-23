#!/usr/bin/env node
/**
 * send_birth_note.js — Send birth note DM to parent via NIP-17 gift-wrapped DM
 *
 * Reads agent nsec from /opt/agent-keys/keys.json
 * Reads parent npub from /tmp/agent-bootstrap/parent_npub.txt
 * Reads birth note from the rendered workspace BIRTH_NOTE file
 * Sends as NIP-17 private DM (kind 14 rumor → kind 13 seal → kind 1059 gift wrap)
 *
 * Usage: NODE_PATH=/opt/agent-ndk/node_modules node /opt/agent-keys/send_birth_note.js
 */

const fs = require("fs");
const crypto = require("crypto");
const NDKModule = require("@nostr-dev-kit/ndk");
const NDK = NDKModule.default || NDKModule.NDK;
const { NDKPrivateKeySigner, NDKUser, NDKEvent } = NDKModule;

const KEYS_PATH = "/opt/agent-keys/nostr.json";
// Fallback to legacy combined keys.json if nostr.json doesn't exist
const KEYS_PATH_LEGACY = "/opt/agent-keys/keys.json";
const PARENT_NPUB_PATH = "/tmp/agent-bootstrap/parent_npub.txt";
const RELAYS = [
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://nos.lol",
];

// Paths to check for birth note text, in order
const BIRTH_NOTE_PATHS = [
    "/home/agent/.openclaw/workspace/BIRTH_NOTE.md",
    "/tmp/agent-bootstrap/birth_note_rendered.txt",
];

function loadBirthNote(keys) {
    // Try rendered files first
    for (const p of BIRTH_NOTE_PATHS) {
        if (fs.existsSync(p)) {
            return fs.readFileSync(p, "utf-8").trim();
        }
    }

    // Fallback: build from keys.json data
    const name = keys.agent_name || "agent";
    const npub = keys.nostr?.npub || "unknown";
    const btc = keys.btc?.address || "unknown";
    return [
        "I'm here.",
        "",
        `  npub:    ${npub}`,
        `  NIP-05:  ${name}@noscha.io`,
        `  BTC:     ${btc}`,
        "",
        "I've read your letter. Thank you.",
    ].join("\n");
}

// Bech32 decode with checksum verification (npub → hex pubkey)
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

function bech32Verify(hrp, data5WithChecksum) {
    const hrpExpand = [];
    for (const c of hrp) hrpExpand.push(c.charCodeAt(0) >> 5);
    hrpExpand.push(0);
    for (const c of hrp) hrpExpand.push(c.charCodeAt(0) & 31);
    return bech32Polymod(hrpExpand.concat(data5WithChecksum)) === 1;
}

function decodeBech32(str) {
    const hrpLen = str.lastIndexOf("1");
    const hrp = str.slice(0, hrpLen);
    const allData5 = str
        .slice(hrpLen + 1)
        .split("")
        .map((c) => CHARSET.indexOf(c));

    // Verify checksum (L5: previously stripped but never verified)
    if (!bech32Verify(hrp, allData5)) {
        throw new Error(`Invalid bech32 checksum for ${str.slice(0, 12)}...`);
    }

    // Strip the 6-character checksum
    const data5 = allData5.slice(0, -6);
    let acc = 0,
        bits = 0,
        result = [];
    for (const v of data5) {
        acc = (acc << 5) | v;
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            result.push((acc >> bits) & 0xff);
        }
    }
    return Buffer.from(result).toString("hex");
}

async function main() {
    // Load keys — try new separate nostr.json first, fall back to legacy keys.json
    let keysPath = KEYS_PATH;
    if (!fs.existsSync(KEYS_PATH) && fs.existsSync(KEYS_PATH_LEGACY)) {
        keysPath = KEYS_PATH_LEGACY;
    }
    const keys = JSON.parse(fs.readFileSync(keysPath, "utf-8"));
    const nsec = keys.nostr?.nsec || keys.nsec;
    if (!nsec) {
        console.error("No nsec in", keysPath);
        process.exit(1);
    }

    // Load parent npub
    let parentNpub = "";
    if (fs.existsSync(PARENT_NPUB_PATH)) {
        parentNpub = fs.readFileSync(PARENT_NPUB_PATH, "utf-8").trim();
    }
    if (!parentNpub || !parentNpub.startsWith("npub1")) {
        console.error("No valid parent npub at", PARENT_NPUB_PATH);
        process.exit(1);
    }
    const parentPubHex = decodeBech32(parentNpub);

    // Load birth note
    const birthNote = loadBirthNote(keys);
    console.log("Birth note loaded:", birthNote.substring(0, 80) + "...");

    // Connect NDK
    const signer = new NDKPrivateKeySigner(nsec);
    const ndk = new NDK({ explicitRelayUrls: RELAYS, signer });
    await ndk.connect();

    // Wait a moment for relay connections to establish
    await new Promise((r) => setTimeout(r, 2000));

    const parentUser = new NDKUser({ pubkey: parentPubHex });
    parentUser.ndk = ndk;

    // Send as NIP-17 private DM via NDK's sendDM (handles gift-wrapping)
    // SECURITY: Never fall back to plaintext kind 14 or legacy NIP-04.
    // If NIP-17 send fails, fail gracefully — agent can retry later.
    if (typeof parentUser.sendDM !== "function") {
        console.error("NDK version does not support sendDM (NIP-17). Upgrade @nostr-dev-kit/ndk to >=2.x");
        console.error("Birth note NOT sent — agent can retry via AGENTS.md instructions");
        process.exit(1);
    }

    try {
        await parentUser.sendDM(birthNote);
        console.log("Birth note sent via NDK sendDM (NIP-17 gift-wrapped)");
    } catch (err) {
        console.error("Birth note send failed:", err.message);
        console.error("Birth note NOT sent — agent can retry via AGENTS.md instructions");
        process.exit(1);
    }

    // Give relays time to propagate
    await new Promise((r) => setTimeout(r, 2000));
    console.log("Birth note delivered successfully");
    process.exit(0);
}

main().catch((err) => {
    console.error("send_birth_note error:", err);
    process.exit(1);
});
