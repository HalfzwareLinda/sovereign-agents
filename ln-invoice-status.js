// Netlify function: Check Lightning invoice payment status
// GET /.netlify/functions/ln-invoice-status?payment_hash=...&order_number=...&agent_config=...
//
// If paid AND agent_config provided, triggers provisioning automatically.

const NWC_SERVICE_URL = process.env.NWC_SERVICE_URL || "http://185.18.221.10:3001";
const PROVISION_URL = process.env.PROVISION_URL || "http://185.18.221.10:3000";
const PROVISION_TOKEN = process.env.PROVISION_TOKEN || "dsc-prov-a7f3e2b1c9d4";

// Track which orders we've already triggered provisioning for (in-memory, resets on redeploy)
const triggeredOrders = new Set();

exports.handler = async (event) => {
    const headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type",
    };

    if (event.httpMethod === "OPTIONS") {
        return { statusCode: 204, headers };
    }

    if (event.httpMethod !== "GET") {
        return { statusCode: 405, headers, body: JSON.stringify({ error: "GET only" }) };
    }

    const params = event.queryStringParameters || {};
    const paymentHash = params.payment_hash;

    if (!paymentHash) {
        return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: "payment_hash required" }),
        };
    }

    try {
        // Check payment status via NWC service
        const statusRes = await fetch(
            `${NWC_SERVICE_URL}/invoice/status/${paymentHash}`
        );

        if (!statusRes.ok) {
            const err = await statusRes.json().catch(() => ({}));
            return {
                statusCode: 502,
                headers,
                body: JSON.stringify({
                    error: "Status check failed",
                    detail: err.error || statusRes.statusText,
                }),
            };
        }

        const status = await statusRes.json();

        // If paid and we have agent config, trigger provisioning (once per order)
        const orderNumber = params.order_number || "";
        if (status.paid && orderNumber && !triggeredOrders.has(orderNumber)) {
            triggeredOrders.add(orderNumber);

            let agentConfig = {};
            try {
                agentConfig = JSON.parse(params.agent_config || "{}");
            } catch (e) {
                // If not JSON in query param, try to reconstruct from order_number
            }

            if (agentConfig.name) {
                console.log(`Payment confirmed for ${orderNumber}, triggering provisioning for ${agentConfig.name}`);

                try {
                    const provRes = await fetch(`${PROVISION_URL}/provision`, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            Authorization: `Bearer ${PROVISION_TOKEN}`,
                        },
                        body: JSON.stringify({
                            order_number: orderNumber,
                            payment_hash: paymentHash,
                            agent_config: agentConfig,
                        }),
                    });
                    const provData = await provRes.json().catch(() => ({}));
                    console.log("Provisioning triggered:", provData);
                    status.provisioning = {
                        triggered: true,
                        job_id: provData.job_id || null,
                        status_url: provData.status_url || null,
                    };
                } catch (provErr) {
                    console.error("Provisioning trigger failed:", provErr.message);
                    status.provisioning = { triggered: false, error: provErr.message };
                    // Remove from triggered set so it can retry
                    triggeredOrders.delete(orderNumber);
                }
            }
        }

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify(status),
        };
    } catch (err) {
        console.error("ln-invoice-status error:", err);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: err.message }),
        };
    }
};
