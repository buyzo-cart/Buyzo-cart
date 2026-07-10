/**
 * Secure Email Utility for Buyzo Cart
 * Handles secure backend email template rendering and SMTP sending via Nodemailer.
 * Does not expose any credentials or keys to the frontend.
 */

const nodemailer = require('nodemailer');
const https = require('https');

// Helper to query Firebase Realtime Database securely via REST API
async function getVaultConfig() {
  const dbUrl = process.env.FIREBASE_DATABASE_URL || "https://buyzocart-default-rtdb.firebaseio.com";
  const dbSecret = process.env.FIREBASE_DB_SECRET; // Secured Netlify environment variable

  if (!dbSecret) {
    console.warn("[Email Utility] FIREBASE_DB_SECRET environment variable is missing. Dynamic configs cannot be retrieved.");
    return null;
  }

  return new Promise((resolve) => {
    const url = `${dbUrl}/owner_vault/config.json?auth=${dbSecret}`;
    https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(JSON.parse(data));
          } else {
            console.error("[Email Utility] Failed to fetch vault config. Status:", res.statusCode, "Response:", data);
            resolve(null);
          }
        } catch (e) {
          console.error("[Email Utility] Error parsing vault config JSON:", e);
          resolve(null);
        }
      });
    }).on('error', (err) => {
      console.error("[Email Utility] Error requesting vault config:", err);
      resolve(null);
    });
  });
}

// Helper to wrap the content in a beautiful Buyzo Cart HTML base template
function getBaseTemplate(title, bodyContent) {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <style>
    body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f8fafc; color: #0f172a; margin: 0; padding: 0; }
    .wrapper { width: 100%; table-layout: fixed; background-color: #f8fafc; padding: 30px 0; }
    .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }
    .header { background: linear-gradient(135deg, #2563eb, #1d4ed8); padding: 30px 20px; text-align: center; color: #ffffff; }
    .header h1 { margin: 0; font-size: 26px; font-weight: 800; letter-spacing: 0.5px; }
    .header .chip { background-color: rgba(255,255,255,0.2); padding: 4px 10px; border-radius: 6px; font-size: 14px; font-weight: 700; margin-right: 6px; display: inline-block; vertical-align: middle; }
    .content { padding: 35px 25px; line-height: 1.6; font-size: 15px; }
    .content h2 { color: #1e3b8a; font-size: 19px; margin-top: 0; margin-bottom: 18px; font-weight: 700; }
    .footer { background-color: #f1f5f9; padding: 20px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #e2e8f0; }
    .footer a { color: #2563eb; text-decoration: none; font-weight: 600; }
    .btn { display: inline-block; background-color: #2563eb; color: #ffffff !important; text-decoration: none; padding: 12px 24px; border-radius: 8px; font-weight: 600; margin-top: 15px; text-align: center; }
    .btn:hover { background-color: #1d4ed8; }
    .table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    .table th { text-align: left; padding: 10px; background-color: #f8fafc; border-bottom: 2px solid #e2e8f0; font-size: 13px; color: #475569; text-transform: uppercase; font-weight: 700; }
    .table td { padding: 12px 10px; border-bottom: 1px solid #e2e8f0; font-size: 14px; }
    .summary-box { background-color: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 15px; margin: 20px 0; }
    .summary-row { display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 14px; }
    .summary-row.total { font-weight: 700; font-size: 16px; border-top: 1px dashed #bfdbfe; padding-top: 8px; margin-top: 8px; color: #1e3a8a; }
    .security-notice { background-color: #fffbeb; border: 1px solid #fef3c7; border-radius: 8px; padding: 15px; color: #92400e; font-size: 13px; margin-top: 20px; }
    .tag { display: inline-block; padding: 3px 8px; border-radius: 20px; font-size: 11px; font-weight: 700; text-transform: uppercase; margin-right: 6px; }
    .tag-success { background-color: #dcfce7; color: #15803d; }
    .tag-warning { background-color: #fef3c7; color: #b45309; }
    .tag-danger { background-color: #fee2e2; color: #b91c1c; }
    .tag-info { background-color: #dbeafe; color: #1d4ed8; }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="container">
      <div class="header">
        <h1><span class="chip">BUYZO</span>Cart</h1>
      </div>
      <div class="content">
        ${bodyContent}
      </div>
      <div class="footer">
        <p>&copy; ${new Date().getFullYear()} Buyzo Cart. All rights reserved.</p>
        <p>If you have any questions, please contact us at <a href="mailto:support@buyzocartshop.com">support@buyzocartshop.com</a></p>
      </div>
    </div>
  </div>
</body>
</html>
`;
}

// Core Email Sending Function
async function sendEmail({ to, subject, html, text }) {
  // Fetch secure config from Firebase
  const vaultConfig = await getVaultConfig();
  const emailConfig = (vaultConfig && vaultConfig.email) || {};

  // Load SMTP configs from vault or fall back to environment variables
  // SMTP Config Placeholder for Owner:
  // - SMTP_HOST
  // - SMTP_PORT
  // - SMTP_USER
  // - SMTP_PASS
  const host = emailConfig.smtpHost || process.env.SMTP_HOST || "";
  const port = parseInt(emailConfig.smtpPort || process.env.SMTP_PORT || "587");
  const user = emailConfig.smtpUser || process.env.SMTP_USER || "";
  const pass = emailConfig.smtpPass || process.env.SMTP_PASS || "";
  const senderEmail = emailConfig.senderEmail || process.env.SENDER_EMAIL || "noreply@buyzocart.shop";
  const senderName = emailConfig.senderName || process.env.SENDER_NAME || "Buyzo Cart";

  console.log(`[Email Utility] Preparing to send email. To: ${to}, Subject: ${subject}`);

  if (!host || !user || !pass) {
    console.warn("[Email Utility] SMTP API/Keys/Credentials are NOT yet configured in Owner Vault or environment variables. Logging email to console.");
    console.log("================= SIMULATED EMAIL DETAILS =================");
    console.log(`To: ${to}`);
    console.log(`Sender: "${senderName}" <${senderEmail}>`);
    console.log(`Subject: ${subject}`);
    console.log(`Body (Plaintext): ${text}`);
    console.log(`Body (HTML): ${html ? "(See below)" : "N/A"}`);
    if (html) {
      console.log("------------------ HTML START ------------------");
      console.log(html);
      console.log("------------------ HTML END ------------------");
    }
    console.log("==========================================================");
    return { success: true, simulated: true };
  }

  try {
    const transporter = nodemailer.createTransport({
      host,
      port,
      secure: port === 465,
      auth: { user, pass }
    });

    const mailOptions = {
      from: `"${senderName}" <${senderEmail}>`,
      to,
      subject,
      text: text || "Please open this email in an HTML-compatible client.",
      html
    };

    const info = await transporter.sendMail(mailOptions);
    console.log("[Email Utility] Email sent successfully. Message ID:", info.messageId);
    return { success: true, messageId: info.messageId };
  } catch (err) {
    console.error("[Email Utility] SMTP Error while sending email:", err);
    return { success: false, error: err.message };
  }
}

// ── TEMPLATE GENERATORS ──

// 1. User Login Notice Email (Login Email)
function getLoginEmailTemplate(userName, email, details = {}) {
  const browser = details.browser || "Unknown";
  const os = details.os || "Unknown";
  const ip = details.ip || "Unknown";
  const location = details.location || "Unknown Location";
  const time = details.time || new Date().toLocaleString('en-IN');
  const device = details.device || "Unknown Device";

  const content = `
    <h2>Login Successful ✅</h2>
    <p>Dear <strong>${userName || 'User'}</strong>,</p>
    <p>Your Buyzo Cart account was recently logged into from a new session. Please verify the login details below:</p>

    <table class="table">
      <tr>
        <td style="width: 140px; font-weight: 600;">Account Email:</td>
        <td>${email}</td>
      </tr>
      <tr>
        <td style="font-weight: 600;">Login Time:</td>
        <td>${time}</td>
      </tr>
      <tr>
        <td style="font-weight: 600;">Device:</td>
        <td>${device}</td>
      </tr>
      <tr>
        <td style="font-weight: 600;">Browser & OS:</td>
        <td>${browser} (${os})</td>
      </tr>
      <tr>
        <td style="font-weight: 600;">IP Address:</td>
        <td>${ip}</td>
      </tr>
      <tr>
        <td style="font-weight: 600;">Location:</td>
        <td>${location}</td>
      </tr>
    </table>

    <div class="security-notice">
      <strong>⚠️ Security Notice:</strong> If this login was authorized by you, no action is required. If you do not recognize this activity, please change your password immediately to protect your account.
    </div>
  `;

  return getBaseTemplate("Successful Login Notice - Buyzo Cart", content);
}

// 2. Order Confirmation Email (Order Email)
function getOrderEmailTemplate(order) {
  const customerName = order.username || order.userInfo?.fullName || "Valued Customer";
  const orderId = order.orderId || "N/A";
  const items = order.items || [];
  const total = order.totalAmount || 0;
  const paymentMethod = (order.paymentMethod || 'prepaid').toUpperCase();
  const paymentStatus = order.paymentMethod === 'prepaid' ? 'SUCCESS' : 'PENDING (COD)';
  const address = order.address || {};
  const date = new Date(order.orderDate || Date.now()).toLocaleDateString('en-IN');

  // Calculate delivery date (usually 4 days from order date)
  const deliveryDateObj = new Date(order.orderDate || Date.now());
  deliveryDateObj.setDate(deliveryDateObj.getDate() + 4);
  const estimatedDelivery = deliveryDateObj.toLocaleDateString('en-IN');

  let itemsHtml = items.map(item => `
    <tr>
      <td>
        <div style="font-weight: 600;">${item.name || 'Product'}</div>
        <div style="font-size: 11px; color: #64748b; margin-top: 2px;">Size: ${item.size || 'N/A'}</div>
      </td>
      <td style="text-align: center;">${item.quantity || 1}</td>
      <td style="text-align: right; font-weight: 600;">₹${(item.price || 0).toLocaleString('en-IN')}</td>
    </tr>
  `).join('');

  const content = `
    <h2>Order Confirmation 🛍️</h2>
    <p>Hi <strong>${customerName}</strong>,</p>
    <p>Thank you for shopping with us! Your order has been placed successfully and is currently being processed. Below are your order details:</p>

    <div style="font-size: 13px; color: #64748b; margin-bottom: 15px;">
      Order Date: <strong>${date}</strong> | Order ID: <strong>${orderId}</strong>
    </div>

    <table class="table">
      <thead>
        <tr>
          <th>Product Details</th>
          <th style="text-align: center; width: 60px;">Qty</th>
          <th style="text-align: right; width: 100px;">Price</th>
        </tr>
      </thead>
      <tbody>
        ${itemsHtml}
      </tbody>
    </table>

    <div class="summary-box">
      <div class="summary-row">
        <span>Subtotal</span>
        <span>₹${(order.subtotal || total - 50).toLocaleString('en-IN')}</span>
      </div>
      <div class="summary-row">
        <span>Delivery Charge</span>
        <span>₹${(order.deliveryCharge || 50).toLocaleString('en-IN')}</span>
      </div>
      ${order.gatewayCharge ? `
      <div class="summary-row">
        <span>Gateway Processing Fee</span>
        <span>₹${order.gatewayCharge.toLocaleString('en-IN')}</span>
      </div>` : ''}
      <div class="summary-row total">
        <span>Grand Total</span>
        <span>₹${total.toLocaleString('en-IN')}</span>
      </div>
    </div>

    <table class="table" style="margin-top: 15px;">
      <tr>
        <td style="font-weight: 600; width: 150px;">Payment Method:</td>
        <td>${paymentMethod} <span class="tag ${order.paymentMethod === 'prepaid' ? 'tag-success' : 'tag-warning'}">${paymentStatus}</span></td>
      </tr>
      <tr>
        <td style="font-weight: 600;">Estimated Delivery:</td>
        <td><strong>${estimatedDelivery}</strong></td>
      </tr>
      <tr>
        <td style="font-weight: 600; vertical-align: top;">Shipping Address:</td>
        <td>
          <strong>${address.name || customerName}</strong><br>
          ${address.street || ''}<br>
          ${address.city || ''}, ${address.state || ''} - ${address.pincode || ''}<br>
          📞 Phone: ${address.mobile || ''}
        </td>
      </tr>
    </table>
  `;

  return getBaseTemplate("Order Confirmed! - Buyzo Cart", content);
}

// 3. Payment Successful Email (Payment Email)
function getPaymentSuccessTemplate(payment) {
  const payId = payment.paymentId || "N/A";
  const rzpOrderId = payment.razorpayOrderId || "N/A";
  const amount = payment.amount || 0;
  const method = (payment.paymentMethod || "prepaid").toUpperCase();
  const time = payment.transactionTime || new Date().toLocaleString('en-IN');

  const content = `
    <h2>Payment Successful 💳</h2>
    <p>Hello,</p>
    <p>Your payment transaction has been processed and verified successfully. Details of the transaction are outlined below:</p>

    <table class="table">
      <tr>
        <td style="width: 150px; font-weight: 600;">Payment Transaction ID:</td>
        <td><strong style="color: #15803d;">${payId}</strong></td>
      </tr>
      <tr>
        <td style="font-weight: 600;">Razorpay Order ID:</td>
        <td>${rzpOrderId}</td>
      </tr>
      <tr>
        <td style="font-weight: 600;">Paid Amount:</td>
        <td><strong style="font-size: 16px; color: #1d4ed8;">₹${amount.toLocaleString('en-IN')}</strong></td>
      </tr>
      <tr>
        <td style="font-weight: 600;">Payment Method:</td>
        <td>${method}</td>
      </tr>
      <tr>
        <td style="font-weight: 600;">Transaction Time:</td>
        <td>${time}</td>
      </tr>
    </table>

    <div style="background-color: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; padding: 15px; color: #166534; font-size: 13px; margin-top: 20px;">
      ✅ Your transaction was verified successfully. The digital invoice is generated and will be sent to your account page. Thanks for your business!
    </div>
  `;

  return getBaseTemplate("Payment Successful! - Buyzo Cart", content);
}

// 4. Payment Failed Email (Payment Email)
function getPaymentFailedTemplate(payment) {
  const rzpOrderId = payment.razorpayOrderId || "N/A";
  const amount = payment.amount || 0;
  const time = payment.transactionTime || new Date().toLocaleString('en-IN');
  const errorMsg = payment.error || "Transaction declined by the gateway.";

  const content = `
    <h2 style="color: #b91c1c;">Payment Transaction Failed ❌</h2>
    <p>Hello,</p>
    <p>We are writing to inform you that your recent payment attempt on Buyzo Cart could not be processed successfully. The transaction details are outlined below:</p>

    <table class="table">
      <tr>
        <td style="width: 150px; font-weight: 600;">Razorpay Order ID:</td>
        <td>${rzpOrderId}</td>
      </tr>
      <tr>
        <td style="font-weight: 600;">Attempted Amount:</td>
        <td><strong>₹${amount.toLocaleString('en-IN')}</strong></td>
      </tr>
      <tr>
        <td style="font-weight: 600;">Failure Time:</td>
        <td>${time}</td>
      </tr>
      <tr>
        <td style="font-weight: 600; color: #b91c1c;">Error Details:</td>
        <td style="color: #b91c1c; font-weight: 600;">${errorMsg}</td>
      </tr>
    </table>

    <div class="security-notice" style="background-color: #fef2f2; border-color: #fee2e2; color: #b91c1c;">
      <strong>⚠️ What should you do?</strong> Your card or bank account has NOT been charged. If money was deducted, it will be automatically refunded by your bank within 3-5 business days. You can try placing the order again using Cash on Delivery (COD) or a different payment method.
    </div>
  `;

  return getBaseTemplate("Payment Failed - Buyzo Cart", content);
}

// 5. Owner Notifications Template
function getOwnerNotificationTemplate(event, details) {
  let title = "System Notification";
  let htmlBody = "";

  switch (event) {
    case "new_order":
      title = "New Order Received! 🛍️";
      htmlBody = `
        <h2>New Order Notification 🛍️</h2>
        <p>A new order has been successfully placed on Buyzo Cart.</p>
        <table class="table">
          <tr><td style="font-weight: 600; width: 140px;">Order ID:</td><td><strong>${details.orderId}</strong></td></tr>
          <tr><td style="font-weight: 600;">Customer Name:</td><td>${details.customerName}</td></tr>
          <tr><td style="font-weight: 600;">Customer Email:</td><td>${details.customerEmail}</td></tr>
          <tr><td style="font-weight: 600;">Items Quantity:</td><td>${details.itemCount} items</td></tr>
          <tr><td style="font-weight: 600;">Total Amount:</td><td><strong>₹${details.total.toLocaleString('en-IN')}</strong></td></tr>
          <tr><td style="font-weight: 600;">Payment Method:</td><td>${details.paymentMethod.toUpperCase()}</td></tr>
        </table>
      `;
      break;

    case "payment_success":
      title = "Prepaid Payment Verified! 💸";
      htmlBody = `
        <h2>Prepaid Payment Verified! 💸</h2>
        <p>A payment transaction has been securely verified on the backend.</p>
        <table class="table">
          <tr><td style="font-weight: 600; width: 140px;">Payment ID:</td><td><strong style="color: #16a34a;">${details.paymentId}</strong></td></tr>
          <tr><td style="font-weight: 600;">Order ID:</td><td>${details.orderId}</td></tr>
          <tr><td style="font-weight: 600;">Amount:</td><td><strong>₹${details.amount.toLocaleString('en-IN')}</strong></td></tr>
          <tr><td style="font-weight: 600;">Time:</td><td>${details.time}</td></tr>
        </table>
      `;
      break;

    case "payment_failed":
      title = "Payment Attempt Failed ❌";
      htmlBody = `
        <h2 style="color: #dc2626;">Payment Failed Notification ❌</h2>
        <p>A customer payment attempt failed during checkout:</p>
        <table class="table">
          <tr><td style="font-weight: 600; width: 140px;">Razorpay Order ID:</td><td>${details.razorpayOrderId}</td></tr>
          <tr><td style="font-weight: 600;">Attempted Amount:</td><td>₹${details.amount.toLocaleString('en-IN')}</td></tr>
          <tr><td style="font-weight: 600;">Error Message:</td><td style="color: #dc2626;">${details.error}</td></tr>
        </table>
      `;
      break;

    case "new_user":
      title = "New User Registration! 🎉";
      htmlBody = `
        <h2>New User Registered! 🎉</h2>
        <p>A new customer has joined the Buyzo Cart platform.</p>
        <table class="table">
          <tr><td style="font-weight: 600; width: 140px;">User Name:</td><td>${details.name}</td></tr>
          <tr><td style="font-weight: 600;">Email Address:</td><td>${details.email}</td></tr>
          <tr><td style="font-weight: 600;">Registered At:</td><td>${new Date().toLocaleString('en-IN')}</td></tr>
        </table>
      `;
      break;

    case "failed_login":
      title = "Failed Login Attempt Alert! ⚠️";
      htmlBody = `
        <h2 style="color: #b45309;">Failed Login Warning ⚠️</h2>
        <p>An unsuccessful login attempt was detected on the site:</p>
        <table class="table">
          <tr><td style="font-weight: 600; width: 140px;">Attempted Email:</td><td><strong>${details.email}</strong></td></tr>
          <tr><td style="font-weight: 600;">Time:</td><td>${details.time}</td></tr>
          <tr><td style="font-weight: 600;">IP Address:</td><td>${details.ip}</td></tr>
          <tr><td style="font-weight: 600;">Browser / OS:</td><td>${details.browser} (${details.os})</td></tr>
        </table>
      `;
      break;

    case "password_changed":
      title = "Security Alert: Master Password Changed 🔐";
      htmlBody = `
        <h2>Security Update: Master Password Changed 🔐</h2>
        <p>This is to notify you that the Master Password for your Owner Vault has been changed successfully.</p>
        <p>Time of update: <strong>${new Date().toLocaleString('en-IN')}</strong></p>
        <p>If you did not authorize this change, please contact support and secure your database immediately.</p>
      `;
      break;

    case "settings_changed":
      title = "System Alert: Sensitive Settings Updated ⚙️";
      htmlBody = `
        <h2>System Notification: Vault Settings Changed ⚙️</h2>
        <p>This is to inform you that sensitive configurations in the Owner Vault have been modified.</p>
        <p>Time of update: <strong>${new Date().toLocaleString('en-IN')}</strong></p>
        <p>Please log in to your Owner Vault to review the changes.</p>
      `;
      break;

    case "refund_initiated":
    case "refund_completed":
      title = `Refund Status Updated: ${event.toUpperCase()}`;
      htmlBody = `
        <h2>Refund Notification: ${event.replace('_', ' ').toUpperCase()}</h2>
        <p>A refund has been updated in the system:</p>
        <table class="table">
          <tr><td style="font-weight: 600; width: 140px;">Order ID:</td><td>${details.orderId}</td></tr>
          <tr><td style="font-weight: 600;">Refunded Amount:</td><td><strong>₹${details.amount.toLocaleString('en-IN')}</strong></td></tr>
          <tr><td style="font-weight: 600;">Date/Time:</td><td>${new Date().toLocaleString('en-IN')}</td></tr>
        </table>
      `;
      break;

    default:
      title = "System Notification";
      htmlBody = `<p>${JSON.stringify(details)}</p>`;
  }

  return getBaseTemplate(title, htmlBody);
}

module.exports = {
  sendEmail,
  getVaultConfig,
  getLoginEmailTemplate,
  getOrderEmailTemplate,
  getPaymentSuccessTemplate,
  getPaymentFailedTemplate,
  getOwnerNotificationTemplate
};
