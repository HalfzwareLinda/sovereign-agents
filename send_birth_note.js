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

const KEYS_PATH = "/opt/agent-keys/keys.json";
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

// Bech32 decode (npub → hex pubkey)
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function decodeBech32(str) {
    const hrpLen = str.lastIndexOf("1");
    const data5 = str
        .slice(hrpLen + 1, -6)
        .split("")
        .map((c) => CHARSET.indexOf(c));
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
    // Load keys
    const keys = JSON.parse(fs.readFileSync(KEYS_PATH, "utf-8"));
    const nsec = keys.nostr?.nsec;
    if (!nsec) {
        console.error("No nsec in", KEYS_PATH);
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

    // Send as NIP-17 private DM (NDK handles gift-wrapping if supported)
    // NDKEvent kind 14 is the NIP-17 private direct message
    try {
        const dmEvent = new NDKEvent(ndk);
        dmEvent.kind = 14;
        dmEvent.content = birthNote;
        dmEvent.tags = [["p", parentPubHex]];

        // NDK's encrypt + gift-wrap flow for NIP-17
        // If NDK supports nip17 send, use it; otherwise fall back to kind 4
        if (typeof parentUser.sendDM === "function") {
            // NDK >=2.x has sendDM which handles NIP-17 gift wrapping
            await parentUser.sendDM(birthNote);
            console.log("Birth note sent via NDK sendDM (NIP-17)");
        } else {
            // Fallback: kind 4 encrypted DM (NIP-04)
            const dm = new NDKEvent(ndk);
            dm.kind = 4;
            dm.content = birthNote;
            dm.tags = [["p", parentPubHex]];
            await dm.encrypt(parentUser);
            await dm.sign();
            await dm.publish();
            console.log("Birth note sent via NIP-04 DM (fallback)");
        }
    } catch (err) {
        console.error("Failed to send via DM, trying raw kind 14:", err.message);
        // Last resort: publish unsigned kind 14 (some relays accept)
        try {
            const raw = new NDKEvent(ndk);
            raw.kind = 14;
            raw.content = birthNote;
            raw.tags = [["p", parentPubHex]];
            await raw.sign();
            await raw.publish();
            console.log("Birth note published as kind 14 (no gift wrap)");
        } catch (err2) {
            console.error("Birth note send failed entirely:", err2.message);
            process.exit(1);
        }
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
