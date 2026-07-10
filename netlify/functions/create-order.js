/**
 * Netlify Serverless Function: create-order
 * Securely creates a Razorpay Order.
 *
 * Secure Backend Integration: NEVER expose your Razorpay Secret Key in frontend code.
 */

// PLACEHOLDERS FOR WEBSITE OWNER:
const RAZORPAY_KEY_ID_PLACEHOLDER = "";     // <-- ADD YOUR RAZORPAY KEY ID HERE
const RAZORPAY_KEY_SECRET_PLACEHOLDER = ""; // <-- ADD YOUR RAZORPAY KEY SECRET HERE

const https = require('https');
const { getVaultConfig } = require('./utils/email');

exports.handler = async function(event, context) {
  // Allow OPTIONS request for CORS if accessed across domains
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "POST, OPTIONS"
      },
      body: ""
    };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      },
      body: JSON.stringify({ error: "Method Not Allowed. Use POST." })
    };
  }

  try {
    const body = JSON.parse(event.body || "{}");
    const amountInINR = parseFloat(body.amount);

    if (!amountInINR || isNaN(amountInINR) || amountInINR <= 0) {
      return {
        statusCode: 400,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*"
        },
        body: JSON.stringify({ error: "Invalid amount. Must be a positive number." })
      };
    }

    // Determine credentials: prioritize database config, then Environment Variables, then placeholders
    let keyId = RAZORPAY_KEY_ID_PLACEHOLDER;
    let keySecret = RAZORPAY_KEY_SECRET_PLACEHOLDER;

    try {
      const vaultConfig = await getVaultConfig();
      if (vaultConfig && vaultConfig.payment) {
        if (vaultConfig.payment.razorpayKeyId) keyId = vaultConfig.payment.razorpayKeyId;
        if (vaultConfig.payment.razorpayKeySecret) keySecret = vaultConfig.payment.razorpayKeySecret;
      }
    } catch (e) {
      console.error("[Razorpay Order] Failed to load config from Owner Vault:", e);
    }

    // Environment variables override database configs
    keyId = process.env.RAZORPAY_KEY_ID || keyId;
    keySecret = process.env.RAZORPAY_KEY_SECRET || keySecret;

    if (!keyId || !keySecret) {
      console.error("[Razorpay] API Key ID or Secret Key is missing.");
      return {
        statusCode: 500,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*"
        },
        body: JSON.stringify({
          error: "Payment Gateway configuration error. Please configure RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET."
        })
      };
    }

    // Razorpay expects amount in paise (1 INR = 100 paise)
    const amountInPaise = Math.round(amountInINR * 100);

    const postData = JSON.stringify({
      amount: amountInPaise,
      currency: "INR",
      receipt: body.receipt || `rcpt_${Date.now()}`,
      payment_capture: 1 // Auto-capture payment after verification
    });

    const authHeader = "Basic " + Buffer.from(`${keyId}:${keySecret}`).toString('base64');

    const options = {
      hostname: 'api.razorpay.com',
      port: 443,
      path: '/v1/orders',
      method: 'POST',
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    };

    const response = await new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        let responseBody = '';
        res.on('data', (chunk) => { responseBody += chunk; });
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            body: responseBody
          });
        });
      });

      req.on('error', (err) => { reject(err); });
      req.write(postData);
      req.end();
    });

    const parsedResponse = JSON.parse(response.body);

    if (response.statusCode >= 200 && response.statusCode < 300) {
      return {
        statusCode: 200,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*"
        },
        body: JSON.stringify({
          order_id: parsedResponse.id,
          amount: parsedResponse.amount,
          currency: parsedResponse.currency,
          key_id: keyId // Safe to send public Key ID to frontend
        })
      };
    } else {
      console.error("[Razorpay API Error]:", parsedResponse);
      return {
        statusCode: response.statusCode,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*"
        },
        body: JSON.stringify({
          error: "Failed to create Razorpay order.",
          details: parsedResponse.error ? parsedResponse.error.description : "Unknown error"
        })
      };
    }

  } catch (err) {
    console.error("[Server Error]:", err);
    return {
      statusCode: 500,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      },
      body: JSON.stringify({ error: "Internal Server Error.", details: err.message })
    };
  }
};
