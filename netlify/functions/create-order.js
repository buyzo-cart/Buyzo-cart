/**
 * Netlify Serverless Function: create-order
 * Securely creates a Razorpay Order.
 *
 * Secure Backend Integration: NEVER expose your Razorpay Secret Key in frontend code.
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

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
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      },
      body: ""
    };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Content-Type': 'application/json'
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
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ error: "Invalid amount. Must be a positive number." })
      };
    }

    // Determine credentials: prioritize database config, then Environment Variables, then placeholders
    let keyId = RAZORPAY_KEY_ID_PLACEHOLDER;
    let keySecret = RAZORPAY_KEY_SECRET_PLACEHOLDER;

    try {
      // Securely retrieve settings from Firebase via Owner Vault configuration
      const vaultConfig = await getVaultConfig();
      if (vaultConfig && vaultConfig.payment) {
        if (vaultConfig.payment.razorpayKeyId) keyId = vaultConfig.payment.razorpayKeyId;
        if (vaultConfig.payment.razorpayKeySecret) keySecret = vaultConfig.payment.razorpayKeySecret;
      }
    } catch (e) {
      console.error("[Razorpay Order] Failed to load config from Owner Vault:", e);
      // Safe fallback inside the catch block to guarantee execution continues
      keyId = process.env.RAZORPAY_KEY_ID || keyId;
      keySecret = process.env.RAZORPAY_KEY_SECRET || keySecret;
    }

    // Environment variables override database configs
    keyId = process.env.RAZORPAY_KEY_ID || keyId;
    keySecret = process.env.RAZORPAY_KEY_SECRET || keySecret;

    if (!keyId || !keySecret) {
      console.error("[Razorpay] API Key ID or Secret Key is missing.");
      return {
        statusCode: 500,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          error: "Payment Gateway configuration error.",
          details: "Razorpay Key ID and Secret are missing. Please configure them in your Owner Vault under payments, or set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET environment variables in your Netlify Site Settings. Also make sure FIREBASE_DB_SECRET is set in Netlify so the serverless function can retrieve settings from the database."
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

    let parsedResponse = {};
    try {
      parsedResponse = JSON.parse(response.body);
    } catch (parseErr) {
      console.error("[Razorpay API] Failed to parse response body:", response.body);
      return {
        statusCode: 500,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          error: "Failed to create Razorpay order.",
          details: `Invalid response from Razorpay API: ${response.body || 'Empty response'}`
        })
      };
    }

    if (response.statusCode >= 200 && response.statusCode < 300) {
      return {
        statusCode: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Content-Type': 'application/json'
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
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Content-Type': 'application/json'
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
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ error: "Internal Server Error.", details: err.message })
    };
  }
};
