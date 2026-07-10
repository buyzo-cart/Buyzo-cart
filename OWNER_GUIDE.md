# Buyzo Cart — Secure Owner Vault Guide 🔐

Welcome to the **Buyzo Cart Owner Vault & Security Management System**. This guide provides step-by-step instructions on setting up, configuring, and maintaining the highly secure Owner Vault, transactional Email API system, and database protection rules.

---

## 🚀 1. First-Time Setup

To initialize the Owner Vault for the first time:

1. **Add Admin Account in Firebase:**
   - Log into your **Firebase Console** and open your Realtime Database.
   - Go to `https://console.firebase.google.com/`.
   - Create a path named `/admins` if it does not exist, and add your Firebase User `UID` as the key, with the boolean value `true`.
     - *Example Structure:*
       ```json
       {
         "admins": {
           "YOUR_FIREBASE_USER_UID": true
         }
       }
       ```
2. **Access the Owner Vault:**
   - Open your browser and navigate to the clean URL: `https://your-domain.com/owner-vault` (or `/owner-vault.html`).
   - Log in using your registered Firebase Admin email and password.
3. **Set the Master Password:**
   - On first setup, the system will detect that no Master Password is set and prompt you to **Create a Master Password**.
   - Input a password (minimum 6 characters) and submit. This password is securely hashed on the backend using SHA-256 with a unique salt. **Never stored in plain text.**

---

## 🔒 2. Managing the Master Password

The Master Password system provides multi-layered brute force lockout and owner-account password resets:

* **Unlocking the Vault:** Every time you visit `/owner-vault`, you will be prompted to enter your Master Password.
* **Brute-Force Lockout:** Entering the password incorrectly 5 times in a row triggers an automatic **15-minute lockout**. Access is suspended on the backend, and a security warning is emailed to the owner's address.
* **Changing the Password:** Under the **Security & PW** tab inside the dashboard, enter your current Master Password, then set and confirm your new Master Password.
* **Forgot Password / Password Reset:** If you forget your Master Password, you can set a brand new password directly without knowing the old one, because you are authenticated via your secure Admin account. Under the **Security & PW** tab, navigate to **Account Password Reset**, input a new password, and click **Reset Master Password**.

---

## 💳 3. Configuring Razorpay API

Under the **Payments** tab inside your Owner Vault, you can manage your payment gateway settings dynamically:

1. **Enter API Keys:**
   - Input your **Razorpay Key ID** and **Razorpay Key Secret** (from your Razorpay Dashboard).
2. **Setup Gateway Surcharge:**
   - Set the **Gateway Surcharge Percent** (e.g., `2` for 2% surcharge on prepaid cards).
3. **Set Delivery Fees:**
   - Set the **Delivery Charge** (e.g., `50` INR) and **Free Shipping Threshold** (e.g., `999` INR to waive delivery charges).
4. **Save Configs:** Click **Save All Configurations** at the bottom. The backend serverless payment functions (`create-order` and `verify-payment`) will automatically load these credentials. No code updates or redeployments required!

---

## ✉️ 4. Configuring the Email API (SMTP)

Under the **Email API** tab, configure your transactional SMTP provider (SendGrid, Mailgun, Resend, Gmail, or any custom SMTP server) to enable automated notification emails:

1. **SMTP Server Details:**
   - **SMTP Host / Server:** e.g., `smtp.sendgrid.net` or `smtp.gmail.com`
   - **SMTP Port:** `587` (TLS) or `465` (SSL)
   - **SMTP Username:** e.g., `apikey` (for SendGrid) or your email address
   - **SMTP Password:** Your SMTP password or API Key Secret
2. **Sender Information:**
   - **Sender Email:** e.g., `noreply@yourdomain.com` (must be verified in your SMTP provider)
   - **Sender Display Name:** e.g., `Buyzo Cart Alerts`
3. **Owner Notifications Email:**
   - Enter your personal/business email under **Owner Notification Receiver Email**.
   - Notifications will be sent here whenever sensitive events occur.

---

## ✉️ 5. Automated Transactional Emails

The system automatically handles transactional emails from the secure backend:

1. **Login Email (Event: `user_login`)**
   - Automatically sent to the customer upon successful login.
   - Contains: User Name, Registered Email, Login Time, Device, Browser, OS, detected IP Address, and Location.
   - Includes a security notice to alert users of unauthorized attempts.
2. **Order Confirmation Email (Event: `order_placed`)**
   - Automatically sent to the customer upon successful order placement (prepaid or COD).
   - Contains: Customer Name, Order ID, detailed Product list, quantities, prices, delivery fee, grand total, payment method, payment status, shipping address, order date, estimated delivery date, and Buyzo Cart branding.
   - Triggers an instant notification to the Owner email ("New order received").
3. **Payment Success Email (Event: `payment_success`)**
   - Triggered securely on the backend when Razorpay payment is verified successfully.
   - Contains: Payment ID, Razorpay Order ID, Amount, Payment Method, and Transaction Time.
   - Triggers a "Prepaid Payment Verified" notification to the Owner.
4. **Payment Failed Email (Event: `payment_failed`)**
   - Sent when a payment attempt fails or signature verification fails.
   - Explains that their card/account has not been charged and details the error.
5. **Owner Notifications**
   - Emails sent to the Owner receiver email for:
     - New order received
     - Payment successful / Payment failed
     - Refund initiated / Refund completed
     - New user registration
     - Failed login attempts
     - Master Password changed
     - Sensitive vault settings updated

---

## 🛠️ 6. System Feature Toggles

Under the **Toggles** tab, you can instantly modify storefront features in real-time:

* **Cash on Delivery (COD):** Instantly enable/disable COD payment option at checkout.
* **Dynamic 2FA Option:** Enable/disable Two-Factor Authentication under user accounts.
* **Ticker Announcement Banner:** Toggle the flat discount ticker announcement above the store hero section.
* **Production/Maintenance Safe Mode:** Puts the entire store in maintenance mode, allowing you to update products without receiving active orders.

---

## 🛡️ 7. Security Recommendations

To ensure your store remains 100% secure:

1. **Database Secrets Environment Variable:**
   - Go to your **Netlify Dashboard -> Site Settings -> Environment Variables**.
   - Add `FIREBASE_DB_SECRET` and set it to your Firebase Realtime Database secret key (found in Firebase Console -> Project Settings -> Service Accounts -> Database Secrets).
   - Add `FIREBASE_DATABASE_URL` (e.g. `https://buyzocart-default-rtdb.firebaseio.com`).
   - Add `FIREBASE_API_KEY` (Your public Firebase API key).
2. **Apply Security Rules:**
   - Copy the contents of `database.rules.json` from this repository.
   - Go to **Firebase Console -> Realtime Database -> Rules**.
   - Overwrite your existing rules with the copied rules and click **Publish**.
   - This ensures that only authorized administrators can read/write the `/owner_vault` and `/admins` paths.
3. **SMTP Authorization:** Always use SSL/TLS (port 465 or 587) with an API Key instead of your personal account password for your SMTP connection to prevent account suspensions.

---
Thank you for using **Buyzo Cart**. For any issues, contact support at `support@buyzocartshop.com`.
