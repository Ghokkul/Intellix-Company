# Intellix — AI Payment Engine

> The most intelligent payment platform ever built.

![Intellix](https://img.shields.io/badge/Intellix-AI%20Payment%20Engine-00e5ff?style=for-the-badge)
![Languages](https://img.shields.io/badge/languages-8-9c6fff?style=for-the-badge)
![Version](https://img.shields.io/badge/version-4.1.0-00e676?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-ffd740?style=for-the-badge)

## Live Demo

Open `index.html` in any browser — zero setup, zero dependencies beyond CDN scripts.

## Pages

| Screen | Description |
|--------|-------------|
| 🏠 **Home** | Landing page · pricing · features · CTA |
| 📊 **Dashboard** | Live KPIs · volume charts · AI fraud shield · predictive analytics |
| 💸 **Payments** | Send · Receive · Swap · Batch · live transaction history · biometric auth |
| 🛡️ **Fraud AI** | Investigation workspace · explainable AI · block/approve/escalate |
| ⚡ **API** | Interactive console · 7 endpoints · live responses · SDK switcher |
| 📱 **Mobile** | Mobile app preview · 3 viral features |
| 🔍 **Smart Shop** | AI product finder · 12 products · 24 stores · price comparison |
| 🔐 **Auth** | Login · 3-step signup · KYC · biometric setup |
| 🗄️ **Database** | Live SQLite · 12 tables · full CRUD · SQL console · analytics |
| `</>`  **Code** | Multi-language showcase · Python · TS · Go · Rust · Solidity · SQL · Swift · Kotlin |

## Payment System

The Payments page is a fully working transaction engine:

- **Send** — 7 currencies (USD, BTC, ETH, USDC, EUR, GBP, SOL), AI Route Optimizer, biometric auth, smart scheduling
- **Receive** — wallet address + QR code per currency
- **Swap** — live rate calculation across any currency pair via Uniswap V3
- **Batch** — multi-recipient single transaction with reduced fees
- **Transaction History** — live feed with filter tabs (All / Confirmed / Pending / Flagged)

## Languages

| Language | Component | Purpose |
|----------|-----------|---------|
| Python 3.12 | `fraud_engine.py` | AI fraud detection with IsolationForest |
| TypeScript 5.3 | `payment.service.ts` | NestJS payment processing service |
| Go 1.22 | `blockchain_listener.go` | Real-time Ethereum block subscription |
| Rust 1.76 | `crypto_engine.rs` | High-performance transaction signing |
| Solidity 0.8.24 | `IntelixVault.sol` | Multi-sig smart contract vault |
| PostgreSQL SQL | `analytics.sql` | Fraud analytics with CTEs + window functions |
| Swift 5.9 | `BiometricAuth.swift` | iOS Face ID / Touch ID authentication |
| Kotlin | `PaymentViewModel.kt` | Android payment ViewModel with coroutines |

## Database (SQLite WASM)

12 live tables — transactions, users, payments, wallets, fraud_alerts, kyc_verifications, currencies, api_keys, webhooks, exchange_rates, audit_logs, products.

Full CRUD · SQL Console · Schema Viewer · Analytics Dashboard · CSV export · Auto audit log


# GitHub Pages — push to repo, enable Pages in Settings
```

## Stack

Pure **HTML5 + CSS3 + Vanilla JS** — no npm, no build step.
External: `sql.js` (SQLite WASM) · Google Fonts · all via CDN.

---

MIT © 2026 Intellix · [github.com/Ghokkul/Intellix-Company](https://github.com/Ghokkul/Intellix-Company)
