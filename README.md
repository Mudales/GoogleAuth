
# GoogleAuth Export Decoder Bot

A Telegram bot that decodes **Google Authenticator export QR codes** and `otpauth-migration://` URIs into standard `otpauth://` TOTP/HOTP URIs — returned as individual messages with a scannable QR code and copyable secret.

---

## Features

- 📷 Scan a Google Authenticator export QR code photo
- 📋 Paste an `otpauth-migration://` URI directly
- 🔑 Returns each account as a separate message with:
  - Issuer, name, secret, and type
  - A freshly generated QR code image
  - Copyable `otpauth://` URI
- Supports TOTP and HOTP accounts

---

## Requirements

- Docker & Docker Compose
- A Telegram Bot Token (via [@BotFather](https://t.me/BotFather))

---

## Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/Mudales/GoogleAuth.git
   cd GoogleAuth
   ```

2. **Create a `.env` file**

   ```env
   TELEGRAM_BOT_TOKEN=your_token_here
   ALLOWED_USER_IDS=123456789,987654321
   ```

3. **Build and run**

   ```bash
   docker compose up -d --build
   ```

---

## Usage

| Input | Description |
|---|---|
| Photo | Send a Google Authenticator export QR code screenshot |
| Text | Paste an `otpauth-migration://` URI |
| `/start` | Display usage instructions |

---

## Project Structure

```
.
├── bot.py                # Main bot logic
├── migration_pb2.py      # Protobuf parser for migration payload
├── requirements.txt      # Python dependencies
├── Dockerfile            # Multi-stage Docker build (python:3.10-slim)
├── docker-compose.yml    # Compose service definition
└── .env                  # Bot token (not committed)
```

---

## Security Notice

> ⚠️ Your OTP secrets are sensitive credentials. Delete the Telegram chat after use and avoid running this bot on a shared or public server.

---

## Environment Variables

| Variable | Description |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Telegram bot token from @BotFather |
| `ALLOWED_USER_IDS` | Comma-separated Telegram user IDs allowed to use the bot. If empty, the bot is open to everyone. |
