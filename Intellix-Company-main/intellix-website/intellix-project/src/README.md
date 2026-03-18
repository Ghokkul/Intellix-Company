# Intellix — Source Code

Real, runnable source files for every layer of the Intellix payment platform.

## Languages

| Dir | File | Language | Version | What it does |
|-----|------|----------|---------|--------------|
| `python/` | `fraud_engine.py` | Python | 3.12 | AI fraud detection (IsolationForest + rule signals) |
| `typescript/` | `payment.service.ts` | TypeScript | 5.3 | NestJS payment processor with route optimization |
| `go/` | `blockchain_listener.go` | Go | 1.22 | Real-time Ethereum block & transaction monitor |
| `rust/` | `crypto_engine.rs` | Rust | 1.76 | ECDSA signing, HD wallet derivation, batch signing |
| `solidity/` | `IntelixVault.sol` | Solidity | 0.8.24 | Multi-sig smart contract vault on Polygon |
| `sql/` | `analytics.sql` | PostgreSQL | 16 | Full schema, RLS, stored procs, fraud analytics |
| `swift/` | `BiometricAuth.swift` | Swift | 5.9 | iOS Face ID/Touch ID + Combine payment flow |
| `kotlin/` | `PaymentViewModel.kt` | Kotlin | 1.9 | Android MVI ViewModel + Room + Retrofit + Hilt |

## Quick Start

### Python — Fraud Engine
```bash
cd python
pip install -r requirements.txt
python fraud_engine.py
```

### TypeScript — Payment Service
```bash
cd typescript
npm install
npx ts-node payment.service.ts
```

### Go — Blockchain Listener
```bash
cd go
go run blockchain_listener.go
```

### Rust — Crypto Engine
```bash
cd rust
rustc crypto_engine.rs -o crypto_engine && ./crypto_engine
# Or with Cargo:
cargo run --release
```

### Solidity — Smart Vault
```bash
# Requires Node.js + Hardhat
npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
npx hardhat compile
npx hardhat test
```

### SQL — Analytics
```bash
psql -U postgres -c "CREATE DATABASE intellix;"
psql -U postgres -d intellix -f sql/analytics.sql
```

### Swift — iOS Auth
```bash
# Open in Xcode 15+ or run via swift-sh:
swift BiometricAuth.swift
```

### Kotlin — Android ViewModel
```bash
# Run as JVM program (no Android SDK needed for demo):
kotlinc PaymentViewModel.kt -include-runtime -d demo.jar
java -jar demo.jar
```

## Architecture

```
                    ┌─────────────────┐
                    │   iOS (Swift)   │  Face ID / Touch ID
                    │  Android (Kotlin)│  Fingerprint / Face
                    └────────┬────────┘
                             │ HTTPS
                    ┌────────▼────────┐
                    │  API Gateway    │  TypeScript / NestJS
                    │  payment.service│
                    └────┬───────┬────┘
                         │       │
              ┌──────────▼──┐ ┌──▼──────────┐
              │ Fraud Engine │ │ Route Optimizer│
              │  (Python)   │ │  (TypeScript)  │
              └──────────┬──┘ └──┬────────────┘
                         │       │
                    ┌────▼───────▼────┐
                    │  PostgreSQL DB  │  SQL / analytics.sql
                    │   (analytics)   │
                    └────────┬────────┘
                             │
              ┌──────────────▼─────────────┐
              │         Blockchain          │
              │   Go listener (Ethereum)    │
              │   Rust crypto engine        │
              │   Solidity vault (Polygon)  │
              └─────────────────────────────┘
```

## GitHub

github.com/Ghokkul/Intellix-Company
