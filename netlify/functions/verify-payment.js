/**
 * Netlify Serverless Function: verify-payment
 * Securely verifies Razorpay payment signature on the backend.
 *
 * Secure Backend Integration: NEVER expose your Razorpay Secret Key in frontend code.
 */

// PLACEHOLDERS FOR WEBSITE OWNER:
const RAZORPAY_KEY_SECRET_PLACEHOLDER = "";    // <-- ADD YOUR RAZORPAY KEY SECRET HERE
const RAZORPAY_WEBHOOK_SECRET_PLACEHOLDER = ""; // <-- ADD YOUR RAZORPAY WEBHOOK SECRET HERE (IF USING WEBHOOKS)

const crypto = require('crypto');
const { getVaultConfig, sendEmail, getPaymentSuccessTemplate, getPaymentFailedTemplate, getOwnerNotificationTemplate } = require('./utils/email');

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
    const { razorpay_payment_id, razorpay_order_id, razorpay_signature, order_id, userEmail, amount } = body;

    // Load configs from Owner Vault
    let keySecret = RAZORPAY_KEY_SECRET_PLACEHOLDER;
    let webhookSecret = RAZORPAY_WEBHOOK_SECRET_PLACEHOLDER;
    let vaultConfig = null;

    try {
      vaultConfig = await getVaultConfig();
      if (vaultConfig && vaultConfig.payment) {
        if (vaultConfig.payment.razorpayKeySecret) keySecret = vaultConfig.payment.razorpayKeySecret;
        if (vaultConfig.payment.razorpayWebhookSecret) webhookSecret = vaultConfig.payment.razorpayWebhookSecret;
      }
    } catch (e) {
      console.error("[Razorpay Verification] Failed to load config from Owner Vault:", e);
    }

    // Environment variables override database configs
    keySecret = process.env.RAZORPAY_KEY_SECRET || keySecret;
    webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET || webhookSecret;

    // Check if this is a standard payment verification request
    if (razorpay_payment_id && razorpay_order_id && razorpay_signature) {

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
        // Trigger customer payment success email & owner notification
        if (userEmail && amount) {
          try {
            const customerHtml = getPaymentSuccessTemplate({
              paymentId: razorpay_payment_id,
              razorpayOrderId: razorpay_order_id,
              amount: parseFloat(amount),
              paymentMethod: "prepaid",
              transactionTime: new Date().toLocaleString('en-IN')
            });
            await sendEmail({
              to: userEmail,
              subject: "Payment Verified Successfully - Buyzo Cart",
              html: customerHtml,
              text: `Payment of ₹${amount} received successfully. Transaction ID: ${razorpay_payment_id}.`
            });

            // Owner Alert
            const ownerEmail = (vaultConfig && vaultConfig.email && vaultConfig.email.receiverEmail) || process.env.SENDER_EMAIL || "buyzocartshop@gmail.com";
            const ownerHtml = getOwnerNotificationTemplate("payment_success", {
              paymentId: razorpay_payment_id,
              orderId: order_id || "N/A",
              amount: parseFloat(amount),
              time: new Date().toLocaleString('en-IN')
            });
            await sendEmail({
              to: ownerEmail,
              subject: `💸 Payment Verified: ₹${amount}`,
              html: ownerHtml,
              text: `A prepaid payment of ₹${amount} was verified. Transaction ID: ${razorpay_payment_id}.`
            });
          } catch (mailErr) {
            console.error("[Razorpay Verification] Failed to send success notifications:", mailErr);
          }
        }

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

        // Trigger payment failed notification
        if (userEmail && amount) {
          try {
            const customerHtml = getPaymentFailedTemplate({
              razorpayOrderId: razorpay_order_id,
              amount: parseFloat(amount),
              transactionTime: new Date().toLocaleString('en-IN'),
              error: "Invalid transaction signature mismatch."
            });
            await sendEmail({
              to: userEmail,
              subject: "Payment Attempt Failed - Buyzo Cart",
              html: customerHtml,
              text: `Your payment of ₹${amount} failed signature verification.`
            });

            // Owner Notification
            const ownerEmail = (vaultConfig && vaultConfig.email && vaultConfig.email.receiverEmail) || process.env.SENDER_EMAIL || "buyzocartshop@gmail.com";
            const ownerHtml = getOwnerNotificationTemplate("payment_failed", {
              razorpayOrderId: razorpay_order_id,
              amount: parseFloat(amount),
              error: "Signature mismatch verification failure."
            });
            await sendEmail({
              to: ownerEmail,
              subject: "⚠️ Alert: Payment Attempt Failed",
              html: ownerHtml,
              text: `Payment verification failed for Razorpay Order: ${razorpay_order_id}.`
            });
          } catch (mailErr) {
            console.error("[Razorpay Verification] Failed to send failure notifications:", mailErr);
          }
        }

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

    // WEBHOOK INTEGRATION:
    const razorpayWebhookSignature = event.headers['x-razorpay-signature'];
    if (razorpayWebhookSignature) {
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
