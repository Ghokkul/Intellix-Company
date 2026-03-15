# Intellix — AI Payment Engine

> The world's most intelligent payment platform, complete with a fully integrated live database system.

![Intellix](https://img.shields.io/badge/Intellix-AI%20Payment%20Engine-00e5ff?style=for-the-badge)
![Version](https://img.shields.io/badge/version-4.0.0-9c6fff?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-00e676?style=for-the-badge)

## Overview

Intellix is a full-stack AI-powered payment platform. Everything runs in a single HTML file — no server, no build step, no dependencies beyond CDN scripts. Open it in a browser and you have a complete, working payment company system.

## Pages

| Screen | Description |
|--------|-------------|
| 🏠 **Home** | Landing page with features, pricing, CTA |
| 📊 **Dashboard** | Live KPIs, volume charts, AI insights, product finder |
| 💸 **Payments** | Full send flow with biometric auth & AI routing |
| 🛡️ **Fraud AI** | Investigation workspace with explainable AI |
| ⚡ **API Console** | Interactive API docs with live request execution |
| 📱 **Mobile** | Mobile app preview + 3 viral features |
| 🔍 **Find Products** | AI-powered product price comparison (12 products, 24 stores) |
| 🔐 **Auth** | Login & 3-step signup with KYC + biometrics |
| 🗄️ **Database** | Full live SQLite database — 12 tables, CRUD, SQL console, analytics |

## Database System (SQLite WASM)

The Database page runs a real in-memory SQLite engine powered by sql.js:

| Table | Records | Description |
|-------|---------|-------------|
| transactions | 15 | Payment transactions with risk scores |
| users | 10 | User profiles, KYC status, tiers |
| payments | 12 | Payment intents with method & routing |
| wallets | 12 | Crypto + fiat wallet balances |
| fraud_alerts | 5 | Flagged transactions with AI signals |
| kyc_verifications | 10 | Identity verification records |
| currencies | 14 | BTC, ETH, USDC, USD, EUR + more |
| api_keys | 6 | API keys with permissions & usage |
| webhooks | 5 | Event subscriptions |
| exchange_rates | 12 | Live FX + crypto rates |
| audit_logs | Auto | Every DB operation logged |
| products | 12 | Smart Shop AI-scored products |

**Features:** Full CRUD on every table · SQL Console with 8 presets · Schema viewer · Analytics dashboard · CSV export · Auto audit log

## Deployment

### GitHub Pages (auto-deploy on push)
The `.github/workflows/deploy.yml` file handles this automatically.

### Netlify Drop
Drag `index.html` to [netlify.com/drop](https://netlify.com/drop)

### Vercel
```bash
npx vercel --yes
```

### Local
```bash
open index.html   # macOS
start index.html  # Windows
```

## Tech Stack
- **Pure HTML5 + CSS3 + Vanilla JS** — zero npm, zero build
- **sql.js** — SQLite compiled to WebAssembly (CDN)
- **Google Fonts** — Syne, JetBrains Mono, Inter
- Single `index.html` file, fully self-contained

## License
MIT © 2026 Intellix
