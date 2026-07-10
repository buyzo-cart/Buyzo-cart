/**
 * Netlify Serverless Function: verify-payment
 * Securely verifies Razorpay payment signature on the backend.
 *
 * Secure Backend Integration: NEVER expose your Razorpay Secret Key in frontend code.
 *
 * =================================================================================
 * CONFIGURATION INSTRUCTIONS FOR WEBSITE OWNER:
 *
 * Option A (Recommended & Secure):
 *   Set the following environment variables in your Netlify Dashboard (Site Settings > Environment Variables):
 *   - RAZORPAY_KEY_SECRET: Your Razorpay API Secret Key (e.g., xxxxxxxxxxxxxxxxxxxxxxxx)
 *   - RAZORPAY_WEBHOOK_SECRET: Your Razorpay Webhook Secret (if using Webhooks, e.g., secret123)
 *
 * Option B (Manual Placeholders):
 *   If not using environment variables, replace the empty strings in the placeholders below
 *   with your actual credentials.
 * =================================================================================
 */

// PLACEHOLDERS FOR WEBSITE OWNER:
const RAZORPAY_KEY_SECRET_PLACEHOLDER = "";    // <-- ADD YOUR RAZORPAY KEY SECRET HERE
const RAZORPAY_WEBHOOK_SECRET_PLACEHOLDER = ""; // <-- ADD YOUR RAZORPAY WEBHOOK SECRET HERE (IF USING WEBHOOKS)

const crypto = require('crypto');

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
    const { razorpay_payment_id, razorpay_order_id, razorpay_signature } = body;

    // Check if this is a standard payment verification request
    if (razorpay_payment_id && razorpay_order_id && razorpay_signature) {
      const keySecret = process.env.RAZORPAY_KEY_SECRET || RAZORPAY_KEY_SECRET_PLACEHOLDER;

      if (!keySecret) {
        console.error("[Razorpay Verification] API Secret Key is missing.");
        return {
          statusCode: 500,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
          },
          body: JSON.stringify({
            error: "Payment Gateway configuration error. Please configure RAZORPAY_KEY_SECRET."
          })
        };
      }

      // Generate the expected signature
      // Signature algorithm: HMAC-SHA256 of "razorpay_order_id|razorpay_payment_id" with key_secret
      const text = razorpay_order_id + "|" + razorpay_payment_id;
      const generatedSignature = crypto
        .createHmac('sha256', keySecret)
        .update(text)
        .digest('hex');

      const isVerified = generatedSignature === razorpay_signature;

      if (isVerified) {
        return {
          statusCode: 200,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
          },
          body: JSON.stringify({
            verified: true,
            message: "Payment signature verified successfully."
          })
        };
      } else {
        console.warn("[Razorpay Verification Failed] Expected: " + generatedSignature + ", Received: " + razorpay_signature);
        return {
          statusCode: 400,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
          },
          body: JSON.stringify({
            verified: false,
            error: "Invalid signature. Payment verification failed."
          })
        };
      }
    }

    // WEBHOOK INTEGRATION PLACEHOLDER:
    // If the request is coming from a Razorpay Webhook instead, verify it using the webhook secret
    const razorpayWebhookSignature = event.headers['x-razorpay-signature'];
    if (razorpayWebhookSignature) {
      const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET || RAZORPAY_WEBHOOK_SECRET_PLACEHOLDER;

      if (!webhookSecret) {
        console.error("[Razorpay Webhook] Webhook Secret is missing.");
        return {
          statusCode: 500,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
          },
          body: JSON.stringify({ error: "Webhook Secret not configured." })
        };
      }

      // Compute Webhook HMAC signature
      const expectedWebhookSig = crypto
        .createHmac('sha256', webhookSecret)
        .update(event.body)
        .digest('hex');

      if (expectedWebhookSig === razorpayWebhookSignature) {
        console.log("[Razorpay Webhook Verified] Event processed successfully.");
        // Process webhook payload (e.g. payment.captured, order.paid etc.)
        return {
          statusCode: 200,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
          },
          body: JSON.stringify({ status: "success", message: "Webhook signature verified." })
        };
      } else {
        console.warn("[Razorpay Webhook Verification Failed]");
        return {
          statusCode: 400,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
          },
          body: JSON.stringify({ error: "Webhook signature mismatch." })
        };
      }
    }

    return {
      statusCode: 400,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      },
      body: JSON.stringify({ error: "Missing required verification fields." })
    };

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
