/**
 * Secure Backend Controller: owner-vault
 * Mapped to /api/owner-vault/*
 * Securely manages the Owner Vault configuration, Master Password setup/verification, lockout tracking, and token verification.
 */

const https = require('https');
const crypto = require('crypto');

// Hashing helper
function hashPassword(password, salt) {
  const finalSalt = salt || "buyzo_secure_salt_2024";
  return crypto.createHmac('sha256', finalSalt).update(password).digest('hex');
}

// Helper to query Firebase Database via REST API using DB Secret or Client ID Token
async function queryFirebase(path, method = 'GET', payload = null, customAuthToken = null) {
  const dbUrl = process.env.FIREBASE_DATABASE_URL || "https://buyzocart-default-rtdb.firebaseio.com";
  const dbSecret = process.env.FIREBASE_DB_SECRET;
  const authToken = customAuthToken || dbSecret;

  if (!authToken) {
    console.warn("[Owner Vault Backend] Neither FIREBASE_DB_SECRET nor customAuthToken is available.");
    return null;
  }

  const url = `${dbUrl}/${path}.json?auth=${authToken}`;
  const postData = payload ? JSON.stringify(payload) : null;

  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const options = {
      hostname: parsedUrl.hostname,
      port: 443,
      path: parsedUrl.pathname + parsedUrl.search,
      method: method,
      headers: {
        'Content-Type': 'application/json',
        ...(postData ? { 'Content-Length': Buffer.byteLength(postData) } : {})
      }
    };

    const req = https.request(options, (res) => {
      let responseBody = '';
      res.on('data', (chunk) => { responseBody += chunk; });
      res.on('end', () => {
        try {
          const parsed = responseBody ? JSON.parse(responseBody) : null;
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(parsed);
          } else {
            reject(new Error(`Firebase Error (Status: ${res.statusCode}): ${JSON.stringify(parsed)}`));
          }
        } catch (e) {
          reject(e);
        }
      });
    });

    req.on('error', (err) => { reject(err); });
    if (postData) req.write(postData);
    req.end();
  });
}

// Helper to verify ID Token with Google identitytoolkit API
async function verifyFirebaseIdToken(idToken) {
  const apiKey = process.env.FIREBASE_API_KEY || "AIzaSyCHFUx3Y1L3mvyLyDMHVKQE6eXi50_fewE";
  const postData = JSON.stringify({ idToken: idToken });

  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'identitytoolkit.googleapis.com',
      port: 443,
      path: `/v1/accounts:lookup?key=${apiKey}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    };

    const req = https.request(options, (res) => {
      let responseBody = '';
      res.on('data', (chunk) => { responseBody += chunk; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(responseBody);
          if (res.statusCode === 200 && parsed.users && parsed.users.length > 0) {
            resolve({
              uid: parsed.users[0].localId,
              email: parsed.users[0].email
            });
          } else {
            reject(new Error(parsed.error ? parsed.error.message : "Invalid ID Token."));
          }
        } catch (e) {
          reject(e);
        }
      });
    });

    req.on('error', (err) => { reject(err); });
    req.write(postData);
    req.end();
  });
}

// Main handler
exports.handler = async function(event, context) {
  // CORS support
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS"
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: corsHeaders, body: "" };
  }

  // Determine sub-action based on endpoint path
  const path = event.path;
  const action = path.split('/').pop();

  try {
    const body = JSON.parse(event.body || "{}");
    const idToken = body.idToken || (event.headers.authorization ? event.headers.authorization.split(' ').pop() : null);

    if (!idToken) {
      return {
        statusCode: 401,
        headers: corsHeaders,
        body: JSON.stringify({ error: "Authentication required. idToken is missing." })
      };
    }

    // 1. Verify user identity & extract verified UID
    const verifiedUser = await verifyFirebaseIdToken(idToken);
    const uid = verifiedUser.uid;

    // 2. Access Control Check: Check if user is listed in /admins or sharedAdminsByUid or is the main store owner
    let isAdmin = false;

    // Check 1: Is this the main owner account?
    if (verifiedUser.email === 'buyzocartshop@gmail.com') {
      isAdmin = true;
    }

    // Check 2: Check /admins
    if (!isAdmin) {
      try {
        const adminVal = await queryFirebase(`admins/${uid}`, 'GET', null, idToken);
        if (adminVal === true || (adminVal && adminVal.isDefault !== undefined)) {
          isAdmin = true;
        }
      } catch (e) {
        console.warn("[Owner Vault Backend] Admin check via ID Token on /admins failed:", e.message);
      }
    }

    if (!isAdmin) {
      try {
        const adminVal = await queryFirebase(`admins/${uid}`);
        if (adminVal === true) {
          isAdmin = true;
        }
      } catch (e) {
        console.warn("[Owner Vault Backend] Admin check via DB Secret on /admins failed:", e.message);
      }
    }

    // Check 3: Check /sharedAdminsByUid
    if (!isAdmin) {
      try {
        const sharedAdminVal = await queryFirebase(`sharedAdminsByUid/${uid}`, 'GET', null, idToken);
        if (sharedAdminVal !== null && sharedAdminVal !== undefined) {
          isAdmin = true;
        }
      } catch (e) {
        console.warn("[Owner Vault Backend] Admin check via ID Token on /sharedAdminsByUid failed:", e.message);
      }
    }

    if (!isAdmin) {
      try {
        const sharedAdminVal = await queryFirebase(`sharedAdminsByUid/${uid}`);
        if (sharedAdminVal !== null && sharedAdminVal !== undefined) {
          isAdmin = true;
        }
      } catch (e) {
        console.warn("[Owner Vault Backend] Admin check via DB Secret on /sharedAdminsByUid failed:", e.message);
      }
    }

    // We only bypass the admin check for "send-email" which is used by authenticated users to send their own transactional emails securely!
    if (action !== "send-email" && isAdmin !== true) {
      console.warn(`[Owner Vault Backend] Unauthorized attempt to access vault by non-admin user UID: ${uid}, Email: ${verifiedUser.email}`);
      return {
        statusCode: 403,
        headers: corsHeaders,
        body: JSON.stringify({ error: "Access Denied. Only authorized owner/admin accounts can access the Owner Vault." })
      };
    }

    // 3. Handle operations
    switch (action) {

      // A. Check Setup Status
      case "status": {
        const security = await queryFirebase('owner_vault/security') || {};
        const isSetup = !!security.password_hash;
        return {
          statusCode: 200,
          headers: corsHeaders,
          body: JSON.stringify({ isSetup })
        };
      }

      // B. First-Time Setup
      case "setup": {
        const password = body.password;
        if (!password || password.length < 6) {
          return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: "Password must be at least 6 characters." }) };
        }

        const security = await queryFirebase('owner_vault/security') || {};
        if (security.password_hash) {
          return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: "Master Password has already been set up." }) };
        }

        const salt = crypto.randomBytes(16).toString('hex');
        const hash = hashPassword(password, salt);

        await queryFirebase('owner_vault/security', 'PUT', {
          password_hash: hash,
          salt: salt,
          failed_attempts: 0,
          locked_until: 0
        });

        // Trigger owner notification
        try {
          const { sendEmail, getOwnerNotificationTemplate } = require('./utils/email');
          const ownerHtml = getOwnerNotificationTemplate("password_changed", {});
          await sendEmail({
            to: verifiedUser.email,
            subject: "Security Alert: Master Password Setup",
            html: ownerHtml,
            text: "The Master Password for your Owner Vault has been set up successfully."
          });
        } catch (mailErr) {
          console.error("[Owner Vault Backend] Error sending alert email:", mailErr);
        }

        return {
          statusCode: 200,
          headers: corsHeaders,
          body: JSON.stringify({ success: true, message: "Master Password set up successfully." })
        };
      }

      // C. Unlock Vault / Verification
      case "unlock": {
        const password = body.password;
        if (!password) {
          return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: "Password is required." }) };
        }

        const security = await queryFirebase('owner_vault/security') || {};
        if (!security.password_hash) {
          return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: "Master Password is not set up yet." }) };
        }

        // Lockout Check
        const now = Date.now();
        if (security.locked_until && security.locked_until > now) {
          const minLeft = Math.ceil((security.locked_until - now) / 60000);
          return {
            statusCode: 423, // Locked
            headers: corsHeaders,
            body: JSON.stringify({ error: `Vault is locked due to multiple incorrect attempts. Try again in ${minLeft} minute(s).` })
          };
        }

        const hash = hashPassword(password, security.salt);
        if (hash === security.password_hash) {
          // Success: Reset failed attempts
          await queryFirebase('owner_vault/security/failed_attempts', 'PUT', 0);
          await queryFirebase('owner_vault/security/locked_until', 'PUT', 0);

          // Generate secure session token
          const token = crypto.randomBytes(32).toString('hex');
          const sessionExpiry = Date.now() + 60 * 60 * 1000; // 1 hour session

          await queryFirebase(`owner_vault/security/sessions/${token}`, 'PUT', {
            uid,
            expiresAt: sessionExpiry,
            createdAt: Date.now()
          });

          return {
            statusCode: 200,
            headers: corsHeaders,
            body: JSON.stringify({ success: true, vaultToken: token, expiresAt: sessionExpiry })
          };
        } else {
          // Failed attempt: increment counter
          const currentAttempts = (security.failed_attempts || 0) + 1;
          const maxAttempts = 5;

          if (currentAttempts >= maxAttempts) {
            // Lockout for 15 minutes
            const lockTime = Date.now() + 15 * 60 * 1000;
            await queryFirebase('owner_vault/security', 'UPDATE', {
              failed_attempts: 0,
              locked_until: lockTime
            });

            // Trigger Owner alert for failed logins
            try {
              const { sendEmail, getOwnerNotificationTemplate } = require('./utils/email');
              const alertHtml = getOwnerNotificationTemplate("failed_login", {
                email: verifiedUser.email,
                time: new Date().toLocaleString('en-IN'),
                ip: event.headers['x-forwarded-for'] || event.headers['client-ip'] || "Unknown",
                browser: event.headers['user-agent'] || "Unknown",
                os: "Server Audit Log"
              });
              await sendEmail({
                to: verifiedUser.email,
                subject: "Security Warning: Owner Vault Locked Out! ⚠️",
                html: alertHtml,
                text: "Your Owner Vault was locked out due to multiple incorrect Master Password attempts."
              });
            } catch (mailErr) {
              console.error("[Owner Vault Backend] Lockout warning email failed:", mailErr);
            }

            return {
              statusCode: 423,
              headers: corsHeaders,
              body: JSON.stringify({ error: "Too many incorrect attempts. Vault has been locked for 15 minutes." })
            };
          } else {
            await queryFirebase('owner_vault/security/failed_attempts', 'PUT', currentAttempts);
            const remaining = maxAttempts - currentAttempts;
            return {
              statusCode: 401,
              headers: corsHeaders,
              body: JSON.stringify({ error: `Incorrect password. ${remaining} attempt(s) remaining.` })
            };
          }
        }
      }

      // D. Get Vault Configuration
      case "get-config": {
        const vaultToken = body.vaultToken;
        if (!vaultToken) {
          return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: "Session token is required." }) };
        }

        // Verify session token
        const session = await queryFirebase(`owner_vault/security/sessions/${vaultToken}`);
        if (!session || session.expiresAt < Date.now()) {
          return { statusCode: 401, headers: corsHeaders, body: JSON.stringify({ error: "Session expired. Please re-enter your Master Password." }) };
        }

        // Retrieve current configurations (or empty object if none exist)
        const config = await queryFirebase('owner_vault/config') || {};
        return {
          statusCode: 200,
          headers: corsHeaders,
          body: JSON.stringify({ config })
        };
      }

      // E. Update Vault Configuration
      case "update-config": {
        const vaultToken = body.vaultToken;
        const newConfig = body.config;

        if (!vaultToken || !newConfig) {
          return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: "Session token and config object are required." }) };
        }

        // Verify session token
        const session = await queryFirebase(`owner_vault/security/sessions/${vaultToken}`);
        if (!session || session.expiresAt < Date.now()) {
          return { statusCode: 401, headers: corsHeaders, body: JSON.stringify({ error: "Session expired." }) };
        }

        // Apply config updates (keep any existing nodes, merge new)
        await queryFirebase('owner_vault/config', 'UPDATE', newConfig);

        // Notify Owner of sensitive setting change
        try {
          const { sendEmail, getOwnerNotificationTemplate } = require('./utils/email');
          const ownerHtml = getOwnerNotificationTemplate("settings_changed", {});
          await sendEmail({
            to: verifiedUser.email,
            subject: "Security Notification: Vault Configuration Updated",
            html: ownerHtml,
            text: "Your Owner Vault configuration has been updated."
          });
        } catch (mailErr) {
          console.error("[Owner Vault Backend] Settings update email failed:", mailErr);
        }

        return {
          statusCode: 200,
          headers: corsHeaders,
          body: JSON.stringify({ success: true, message: "Configuration saved successfully." })
        };
      }

      // F. Change Master Password
      case "change-password": {
        const vaultToken = body.vaultToken;
        const currentPassword = body.currentPassword;
        const newPassword = body.newPassword;

        if (!vaultToken || !currentPassword || !newPassword || newPassword.length < 6) {
          return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: "Invalid inputs. Password must be at least 6 characters." }) };
        }

        // Verify session token
        const session = await queryFirebase(`owner_vault/security/sessions/${vaultToken}`);
        if (!session || session.expiresAt < Date.now()) {
          return { statusCode: 401, headers: corsHeaders, body: JSON.stringify({ error: "Session expired." }) };
        }

        const security = await queryFirebase('owner_vault/security') || {};
        const oldHash = hashPassword(currentPassword, security.salt);

        if (oldHash !== security.password_hash) {
          return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: "Current Master Password is incorrect." }) };
        }

        const newSalt = crypto.randomBytes(16).toString('hex');
        const newHash = hashPassword(newPassword, newSalt);

        await queryFirebase('owner_vault/security', 'UPDATE', {
          password_hash: newHash,
          salt: newSalt,
          failed_attempts: 0
        });

        // Notify Owner
        try {
          const { sendEmail, getOwnerNotificationTemplate } = require('./utils/email');
          const ownerHtml = getOwnerNotificationTemplate("password_changed", {});
          await sendEmail({
            to: verifiedUser.email,
            subject: "Security Alert: Master Password Changed",
            html: ownerHtml,
            text: "Your Master Password has been changed successfully."
          });
        } catch (mailErr) {
          console.error("[Owner Vault] Alert email failed:", mailErr);
        }

        return {
          statusCode: 200,
          headers: corsHeaders,
          body: JSON.stringify({ success: true, message: "Master Password changed successfully." })
        };
      }

      // G. Reset Master Password (Authenticated Reset)
      case "reset-password": {
        const newPassword = body.newPassword;
        if (!newPassword || newPassword.length < 6) {
          return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: "Password must be at least 6 characters." }) };
        }

        // Directly allow reset because the user is fully logged in and verified as the authenticated Admin/Owner via Google Auth!
        const newSalt = crypto.randomBytes(16).toString('hex');
        const newHash = hashPassword(newPassword, newSalt);

        await queryFirebase('owner_vault/security', 'UPDATE', {
          password_hash: newHash,
          salt: newSalt,
          failed_attempts: 0,
          locked_until: 0
        });

        // Notify Owner
        try {
          const { sendEmail, getOwnerNotificationTemplate } = require('./utils/email');
          const ownerHtml = getOwnerNotificationTemplate("password_changed", {});
          await sendEmail({
            to: verifiedUser.email,
            subject: "Security Warning: Master Password Reset",
            html: ownerHtml,
            text: "The Master Password for your Owner Vault has been reset successfully via your Owner account."
          });
        } catch (mailErr) {
          console.error("[Owner Vault] Alert email failed:", mailErr);
        }

        return {
          statusCode: 200,
          headers: corsHeaders,
          body: JSON.stringify({ success: true, message: "Master Password has been reset successfully." })
        };
      }

      // H. Send Transactional Email
      case "send-email": {
        const eventType = body.eventType; // 'user_login', 'order_placed', 'new_user_registration'
        const { sendEmail, getLoginEmailTemplate, getOrderEmailTemplate, getOwnerNotificationTemplate } = require('./utils/email');
        const vaultConfig = await queryFirebase('owner_vault/config') || {};

        if (eventType === 'user_login') {
          const deviceDetails = body.deviceDetails || {};
          const userHtml = getLoginEmailTemplate(verifiedUser.email.split('@')[0], verifiedUser.email, {
            browser: deviceDetails.browser,
            os: deviceDetails.os,
            ip: event.headers['x-forwarded-for'] || event.headers['client-ip'] || "Unknown",
            location: deviceDetails.location || "Unknown Location",
            time: new Date().toLocaleString('en-IN'),
            device: deviceDetails.device || "Unknown Device"
          });

          // Send to user
          await sendEmail({
            to: verifiedUser.email,
            subject: "Successful Login Notice - Buyzo Cart",
            html: userHtml,
            text: `Successful login to Buyzo Cart from device: ${deviceDetails.device || 'Unknown'}`
          });

          // Send alert to owner
          const ownerEmail = (vaultConfig.email && vaultConfig.email.receiverEmail) || "buyzocartshop@gmail.com";
          const ownerHtml = getOwnerNotificationTemplate("failed_login", {
            email: verifiedUser.email,
            time: new Date().toLocaleString('en-IN'),
            ip: event.headers['x-forwarded-for'] || event.headers['client-ip'] || "Unknown",
            browser: deviceDetails.browser || "Unknown",
            os: deviceDetails.os || "Unknown"
          });
          await sendEmail({
            to: ownerEmail,
            subject: `🔐 Security Alert: Successful Admin/User Login - ${verifiedUser.email}`,
            html: ownerHtml,
            text: `User ${verifiedUser.email} logged in from IP ${event.headers['x-forwarded-for'] || 'Unknown'}`
          });

          return { statusCode: 200, headers: corsHeaders, body: JSON.stringify({ success: true }) };
        }

        if (eventType === 'order_placed') {
          const orderId = body.orderId;
          if (!orderId) {
            return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: "orderId is required." }) };
          }

          // Fetch order from Firebase using admin access
          const order = await queryFirebase(`orders/${orderId}`, 'GET', null, idToken);
          if (!order) {
            return { statusCode: 404, headers: corsHeaders, body: JSON.stringify({ error: "Order not found." }) };
          }

          // Verify that this order belongs to the verified user (or the user is an admin)
          if (order.userId !== uid && isAdmin !== true) {
            return { statusCode: 403, headers: corsHeaders, body: JSON.stringify({ error: "Access Denied. Order mismatch." }) };
          }

          // Generate template and send email to customer
          const customerHtml = getOrderEmailTemplate(order);
          await sendEmail({
            to: verifiedUser.email,
            subject: `Order Confirmed! Order ID: ${orderId} - Buyzo Cart`,
            html: customerHtml,
            text: `Thank you for your order! Your Order ID is ${orderId}.`
          });

          // Send notification to Owner
          const ownerEmail = (vaultConfig.email && vaultConfig.email.receiverEmail) || "buyzocartshop@gmail.com";
          const ownerHtml = getOwnerNotificationTemplate("new_order", {
            orderId: orderId,
            customerName: order.username || order.userInfo?.fullName || verifiedUser.email.split('@')[0],
            customerEmail: verifiedUser.email,
            itemCount: (order.items || []).length || 1,
            total: order.totalAmount || 0,
            paymentMethod: order.paymentMethod || 'prepaid'
          });
          await sendEmail({
            to: ownerEmail,
            subject: `🛍️ New Order Received: ${orderId} (₹${order.totalAmount || 0})`,
            html: ownerHtml,
            text: `New order placed by ${verifiedUser.email}. Order ID: ${orderId}.`
          });

          return { statusCode: 200, headers: corsHeaders, body: JSON.stringify({ success: true }) };
        }

        if (eventType === 'new_user_registration') {
          const userName = body.userName || verifiedUser.email.split('@')[0];

          // Send to owner
          const ownerEmail = (vaultConfig.email && vaultConfig.email.receiverEmail) || "buyzocartshop@gmail.com";
          const ownerHtml = getOwnerNotificationTemplate("new_user", {
            name: userName,
            email: verifiedUser.email
          });
          await sendEmail({
            to: ownerEmail,
            subject: `🎉 New User Registered: ${verifiedUser.email}`,
            html: ownerHtml,
            text: `New user registration. Email: ${verifiedUser.email}, Name: ${userName}.`
          });

          return { statusCode: 200, headers: corsHeaders, body: JSON.stringify({ success: true }) };
        }

        return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: "Unsupported eventType." }) };
      }

      default: {
        return {
          statusCode: 404,
          headers: corsHeaders,
          body: JSON.stringify({ error: `Action '${action}' not found.` })
        };
      }
    }

  } catch (err) {
    console.error("[Owner Vault Backend Exception]:", err);
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: "Internal Server Error.", details: err.message })
    };
  }
};
