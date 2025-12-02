# Secure End-to-End Encrypted Messaging & File-Sharing System

## Project Overview
This is a semester project for Information Security (BSSE 7th Semester) that implements a secure communication system with end-to-end encryption for text messaging and file sharing.

## Current Implementation Status
- ✅ Part 1: User Authentication (Basic)
- ✅ Part 2: Key Generation & Secure Key Storage
- ⏳ Part 3: Secure Key Exchange Protocol (Pending)
- ⏳ Part 4: End-to-End Message Encryption (Pending)
- ⏳ Part 5: Encrypted File Sharing (Pending)

## Project Structure
```
REProject/
├── backend/          # Node.js + Express server
├── frontend/         # React.js client
├── docs/            # Documentation and reports
└── README.md        # This file
```

## Setup Instructions

### Prerequisites
- Node.js (v16 or higher)
- MongoDB (local or MongoDB Atlas)
- npm or yarn

### Backend Setup
```bash
cd backend
npm install
cp .env.example .env
# Edit .env with your MongoDB URI and JWT secret
npm start
```

### Frontend Setup
```bash
cd frontend
npm install
npm start
```

## Technology Stack
- **Frontend:** React.js, Web Crypto API, IndexedDB
- **Backend:** Node.js, Express, MongoDB
- **Security:** bcrypt, Web Crypto API (SubtleCrypto)

## Security Features
- Password hashing with bcrypt
- Client-side key generation (RSA-2048 or ECC P-256)
- Private keys stored only in IndexedDB (never on server)
- Public keys stored on server for key exchange

## Development Notes
- All encryption occurs client-side
- Private keys never leave the client device
- No plaintext stored on server
- HTTPS required for production

