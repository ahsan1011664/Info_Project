## Backend – Secure Messaging & Key Exchange

### 1. Overview

- **Stack**: Node.js, Express, MongoDB (Atlas or local).
- **Features**:
  - User registration + login with bcrypt + JWT.
  - Storage of users’ **long‑term RSA public keys** (signing keys).
  - Simple relay API for **key‑exchange messages** (no plaintext content).

### 2. Setup

1. Install dependencies:

```bash
cd backend
npm install
```

2. Configure environment in `.env`:

```ini
MONGODB_URI=your-mongodb-uri-here
PORT=5000
JWT_SECRET=your-jwt-secret
CORS_ORIGIN=http://localhost:3000
```

3. Run the server:

```bash
node server.js
```

You should see:

- `✅ Environment variables loaded from .env file`
- `🚀 Server running on port 5000`
- `✅ Connected to MongoDB`

### 3. Main Endpoints

- `POST /api/auth/register` – create user (username + password).
- `POST /api/auth/login` – login, returns JWT.
- `POST /api/auth/update-public-key` – save user’s RSA public key (called by frontend).
- `GET /api/auth/public-key/:username` – fetch another user’s public key.

**Key exchange relay:**

- `POST /api/kx/send`
  - Auth: `Authorization: Bearer <JWT>`.
  - Body: `{ to, messageType, payload }`.
  - Stores message in memory and logs:
    - `[KX] Message queued: type=..., from=..., to=...`.

- `GET /api/kx/inbox`
  - Auth: `Authorization: Bearer <JWT>`.
  - Returns and removes all pending messages for the authenticated user.
  - Logs:
    - `[KX] Delivering N message(s) to <username> ...`.

The backend **never** sees private keys or plaintext message content.


