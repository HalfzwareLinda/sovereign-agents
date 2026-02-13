// Netlify function: Create Lightning invoice via NWC service
// POST /.netlify/functions/ln-create-invoice
// Body: { amount_usd, tier, order_number, agent_config }

const NWC_SERVICE_URL = process.env.NWC_SERVICE_URL || "http://185.18.221.10:3001";
const PROVISION_TOKEN = process.env.PROVISION_TOKEN || "dsc-prov-a7f3e2b1c9d4";

// Tier pricing in USD
const TIER_PRICES = {
    seed: 99,
    evolve: 149,
    dynasty: 299,
    trial: 5,
};

// BTC/USD rate — updated periodically, fallback to conservative estimate
async function getSatsPerUsd() {
    try {
        const res = await fetch("https://mempool.space/api/v1/prices");
        if (res.ok) {
            const data = await res.json();
            const btcUsd = data.USD;
            if (btcUsd > 0) return Math.round(100_000_000 / btcUsd);
        }
    } catch (e) {
        // fallback
    }
    // Fallback: ~$100k/BTC = 1000 sats/USD
    return 1000;
}

exports.handler = async (event) => {
    const headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type",
    };

    if (event.httpMethod === "OPTIONS") {
        return { statusCode: 204, headers };
    }

    if (event.httpMethod !== "POST") {
        return { statusCode: 405, headers, body: JSON.stringify({ error: "POST only" }) };
    }

    try {
        const body = JSON.parse(event.body || "{}");
        const tier = body.tier || "seed";
        const orderNumber = body.order_number || `ord-${Date.now().toString(36)}`;
        const agentConfig = body.agent_config || {};

        // Determine amount
        let amountUsd = body.amount_usd || TIER_PRICES[tier] || 99;
        const satsPerUsd = await getSatsPerUsd();
        const amountSats = Math.round(amountUsd * satsPerUsd);

        const memo = `Sovereign Agent: ${agentConfig.name || "agent"} (${tier})`;

        // Call NWC invoice service
        const invoiceRes = await fetch(`${NWC_SERVICE_URL}/invoice/create`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${PROVISION_TOKEN}`,
            },
            body: JSON.stringify({
                amount_sats: amountSats,
                memo,
                order_number: orderNumber,
            }),
        });

        if (!invoiceRes.ok) {
            const err = await invoiceRes.json().catch(() => ({}));
            return {
                statusCode: 502,
                headers,
                body: JSON.stringify({
                    error: "Invoice creation failed",
                    detail: err.error || invoiceRes.statusText,
                }),
            };
        }

        const invoice = await invoiceRes.json();

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                bolt11: invoice.bolt11,
                payment_hash: invoice.payment_hash,
                amount_sats: amountSats,
                amount_usd: amountUsd,
                order_number: orderNumber,
                tier,
            }),
        };
    } catch (err) {
        console.error("ln-create-invoice error:", err);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: err.message }),
        };
    }
};
