#!/usr/bin/env node
/**
 * server.js — Provisioning Server
 *
 * Receives payment confirmations (from Plisio callback or direct API)
 * and spawns create_vm.py to provision agent VPS instances.
 *
 * Endpoints:
 *   POST /provision          — trigger provisioning (requires auth token)
 *   GET  /provision/:id      — check provisioning status
 *   GET  /health             — health check
 *
 * Environment:
 *   PROVISION_TOKEN          — bearer token for auth
 *   PROVISION_DIR            — path to provisioning scripts (default: /opt/provision)
 *   PAYPERQ_API_KEY          — passed through to create_vm.py
 *   NWC_CONNECTION_STRING    — NWC string for auto-paying Lightning invoices
 *   PORT                     — server port (default: 3000)
 */

const http = require("http");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const PORT = parseInt(process.env.PORT || "3000", 10);
const PROVISION_TOKEN = process.env.PROVISION_TOKEN || "dsc-prov-a7f3e2b1c9d4";
const PROVISION_DIR = process.env.PROVISION_DIR || "/opt/provision";

// In-memory job tracking
const jobs = new Map();

function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function parseBody(req) {
    return new Promise((resolve, reject) => {
        let body = "";
        req.on("data", (chunk) => (body += chunk));
        req.on("end", () => {
            try {
                resolve(body ? JSON.parse(body) : {});
            } catch (e) {
                reject(new Error("Invalid JSON"));
            }
        });
        req.on("error", reject);
    });
}

function jsonResponse(res, status, data) {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(data));
}

function authenticate(req) {
    const auth = req.headers.authorization || "";
    return auth === `Bearer ${PROVISION_TOKEN}`;
}

function runProvision(agentConfig) {
    const jobId = generateId();
    const name = (agentConfig.name || "agent").toLowerCase().replace(/[^a-z0-9-]/g, "");
    const brand = agentConfig.brand || "descendant";
    const tier = agentConfig.tier || "seed";
    const parentNpub = agentConfig.parent_npub || "";
    const personality = agentConfig.personality || "professional";
    const mission = agentConfig.mission || "";

    const job = {
        id: jobId,
        name,
        status: "running",
        started_at: new Date().toISOString(),
        finished_at: null,
        exit_code: null,
        output: "",
        error: "",
        summary: null,
    };
    jobs.set(jobId, job);

    const args = [
        path.join(PROVISION_DIR, "create_vm.py"),
        "--name", name,
        "--brand", brand,
        "--tier", tier,
        "--parent-npub", parentNpub,
        "--personality", personality,
        "--mission", mission,
    ];

    console.log(`[${jobId}] Starting provisioning: ${name} (${tier}/${brand})`);
    console.log(`[${jobId}] Personality: ${personality}`);
    if (mission) console.log(`[${jobId}] Mission: ${mission.substring(0, 100)}...`);

    const env = {
        ...process.env,
        PAYPERQ_API_KEY: process.env.PAYPERQ_API_KEY || "",
    };

    const proc = spawn("python3", args, {
        cwd: PROVISION_DIR,
        env,
        stdio: ["ignore", "pipe", "pipe"],
    });

    proc.stdout.on("data", (data) => {
        const text = data.toString();
        job.output += text;
        // Log last line for progress
        const lines = text.trim().split("\n");
        const last = lines[lines.length - 1];
        if (last) console.log(`[${jobId}] ${last}`);
    });

    proc.stderr.on("data", (data) => {
        job.error += data.toString();
    });

    proc.on("close", (code) => {
        job.status = code === 0 ? "completed" : "failed";
        job.exit_code = code;
        job.finished_at = new Date().toISOString();
        console.log(`[${jobId}] Finished: ${job.status} (exit ${code})`);

        // Try to read summary JSON
        const summaryPath = path.join(PROVISION_DIR, `vm_${name}_summary.json`);
        try {
            if (fs.existsSync(summaryPath)) {
                job.summary = JSON.parse(fs.readFileSync(summaryPath, "utf-8"));
            }
        } catch (e) {
            console.warn(`[${jobId}] Could not read summary: ${e.message}`);
        }
    });

    proc.on("error", (err) => {
        job.status = "failed";
        job.error = err.message;
        job.finished_at = new Date().toISOString();
        console.error(`[${jobId}] Process error: ${err.message}`);
    });

    return jobId;
}

const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${PORT}`);

    // Health check
    if (req.method === "GET" && url.pathname === "/health") {
        return jsonResponse(res, 200, { status: "ok", jobs: jobs.size });
    }

    // Provision status
    const statusMatch = url.pathname.match(/^\/provision\/(.+)$/);
    if (req.method === "GET" && statusMatch) {
        const jobId = statusMatch[1];
        const job = jobs.get(jobId);
        if (!job) return jsonResponse(res, 404, { error: "Job not found" });
        return jsonResponse(res, 200, {
            id: job.id,
            name: job.name,
            status: job.status,
            started_at: job.started_at,
            finished_at: job.finished_at,
            summary: job.summary,
        });
    }

    // Trigger provisioning
    if (req.method === "POST" && url.pathname === "/provision") {
        if (!authenticate(req)) {
            return jsonResponse(res, 401, { error: "Unauthorized" });
        }

        try {
            const body = await parseBody(req);
            const agentConfig = body.agent_config || body;

            if (!agentConfig.name) {
                return jsonResponse(res, 400, { error: "agent_config.name required" });
            }

            const jobId = runProvision(agentConfig);
            return jsonResponse(res, 202, {
                job_id: jobId,
                status: "running",
                status_url: `/provision/${jobId}`,
            });
        } catch (err) {
            return jsonResponse(res, 400, { error: err.message });
        }
    }

    jsonResponse(res, 404, { error: "Not found" });
});

server.listen(PORT, () => {
    console.log(`Provisioning server listening on port ${PORT}`);
    console.log(`  PROVISION_DIR: ${PROVISION_DIR}`);
    console.log(`  Auth token: ${PROVISION_TOKEN.substring(0, 8)}...`);
});
