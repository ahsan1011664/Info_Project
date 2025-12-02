## Frontend – Secure E2EE Client & Key Exchange Demo

### 1. Overview

- **Stack**: React, Axios, Web Crypto API, IndexedDB.
- **Features**:
  - Registration + login UI.
  - Local generation and storage of **RSA‑2048 signing keys** (identity keys).
  - Dashboard showing key status.
  - **Secure Key Exchange Demo** implementing:
    - Ephemeral **ECDH P‑256**.
    - RSA digital signatures.
    - Session key derivation via **HKDF‑SHA‑256** → AES‑256‑GCM.
    - Encrypted **key‑confirmation** messages.

### 2. Setup

1. Install dependencies:

```bash
cd frontend
npm install
```

2. Configure API URL (optional):

- By default, frontend uses `http://localhost:5000/api`.
- To override, set in `.env`:

```ini
REACT_APP_API_URL=http://localhost:5000/api
```

3. Run the frontend:

```bash
npm start
```

The app will open at `http://localhost:3000`.

### 3. Secure Key Exchange Demo – How to Run

Use **two different browser contexts** (e.g., Chrome + Incognito/Firefox).

1. **Create users**
   - In one browser, register user `Bilal`.
   - In another browser, register user `Maaz`.

2. **Log in**
   - Chrome (normal): log in as `Bilal`.
   - Chrome Incognito / Firefox: log in as `Maaz`.
   - On both Dashboards, confirm under **Cryptographic Keys**:
     - `Private Key: ✅ Stored Locally`

3. **Run the key exchange**

**On Bilal’s Dashboard (initiator):**
- In **Secure Key Exchange Demo (ECDH + Signatures)** card:
  - Peer Username: `Maaz`
  - Click **Start Key Exchange (Initiator)**.
- Protocol Status should show:
  - `KEY_INIT sent to server`

**On Maaz’s Dashboard (responder):**
- Click **Check Inbox / Process Messages**.
- You should see:
  - `Received KEY_INIT from Bilal`
  - `Processed KEY_INIT, sent KEY_RESP`

**Back on Bilal’s Dashboard:**
- Click **Check Inbox / Process Messages** again.
- You should see:
  - `Received KEY_RESP from Maaz`
  - `Derived session key and sent KEY_CONFIRM_A`

**Back on Maaz’s Dashboard:**
- Click **Check Inbox / Process Messages**.
- You should see:
  - `Received KEY_CONFIRM_A from Bilal`
  - `KEY_CONFIRM_A verified, sending KEY_CONFIRM_B`

**Finally on Bilal’s Dashboard:**
- Click **Check Inbox / Process Messages**.
- You should see:
  - `Received KEY_CONFIRM_B from Maaz`
  - `KEY_CONFIRM_B verified. Secure session established!`

These logs are your evidence that:

- ECDH + RSA signatures + HKDF‑SHA‑256 were executed.
- Both sides derived the same AES‑256‑GCM session key.
- The final **key confirmation** succeeded.


