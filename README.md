# 🛡️ ZeroTrustPay — Secure SDLC Engineering Workbench

<div align="center">

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.3%2B-000000?style=for-the-badge&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-WAL%20Mode-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![pytest](https://img.shields.io/badge/pytest-66%2F66%20Passed-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)
![Zero Trust](https://img.shields.io/badge/Security-Zero%20Trust%20DbC-10B981?style=for-the-badge&logo=shield&logoColor=white)

**A Production-Grade Secure SDLC Workbench & FinTech Banking Application**  
*Proving that security is mathematically engineered into every phase of the Software Development Life Cycle—not just bolted on at the end.*

[Overview](#-overview) • [Why Design-by-Contract?](#-why-design-by-contract-dbc) • [The 4 Secure SDLC Phases](#-the-4-secure-sdlc-phases) • [Live Attack Demos](#-red-team-attack-simulator) • [Automated Tests](#-automated-verification-suite) • [Quick Start](#-quick-start-guide)

</div>

---

## 📖 Overview

**ZeroTrustPay** is an enterprise-grade Secure Software Engineering (SSE) academic project and interactive workbench. It solves a fundamental problem in real-world software development:

> ⚠️ **The Bolted-On Security Fallacy:** Most software projects write business code first, and then add web firewalls or basic login checks at the very end. When attackers find race conditions, SQL injections, or tamper with the database directly, the entire system collapses.

### The ZeroTrustPay Solution
ZeroTrustPay implements **Meyer's Design-by-Contract (DbC)** directly at function boundaries. Every single financial transaction is guarded by:
1. **Pre-Conditions:** Strict typing, bounded amounts (`0 < amt <= 50,000`), anti-replay nonces, and HMAC-SHA256 integrity signatures.
2. **System Invariants:** A cryptographic **SHA-256 Hash-Chained Ledger** (mini-blockchain). If an insider directly edits SQLite, the broken hash triggers an automatic **Circuit Breaker** that freezes the system.
3. **Post-Conditions:** A mathematical **Conservation of Money Law** (`Sb + Rb == Sa + Ra`) asserting that money cannot be created or destroyed.

---

## 🏛️ System Architecture & Trust Boundaries

```
┌────────────────────────────────────────────────────────────────────────┐
│                        TRUST BOUNDARY ARCHITECTURE                     │
│                                                                        │
│   ┌──────────────────┐      ┌───────────────────────────────────────┐  │
│   │   BOUNDARY 1     │      │   BOUNDARY 2: Security Middleware     │  │
│   │   Untrusted      │─────▶│   @secure_contract Decorator          │  │
│   │   Client Browser │      │   ├─ PC-1: Schema & Type Validation   │  │
│   │   (REST Fetch)   │      │   ├─ PC-2: Amount Bounds (0, 50k]     │  │
│   └──────────────────┘      │   ├─ PC-3: Self-Transfer Rejection    │  │
│                             │   ├─ PC-4: Anti-Replay Nonce Check    │  │
│                             │   ├─ PC-5: HMAC-SHA256 Payload Hash   │  │
│                             │   ├─ PC-6: Contextual Risk Scoring    │  │
│                             │   ├─ INV:  SHA-256 Ledger Chain Scan  │  │
│                             │   ├─ MUTEX: Atomic BEGIN EXCLUSIVE    │  │
│                             │   └─ POST: Conservation of Money Law  │  │
│                             └───────────────────┬───────────────────┘  │
│                                                 │                      │
│                             ┌───────────────────▼───────────────────┐  │
│                             │   BOUNDARY 3: Cryptographic Storage   │  │
│                             │   SQLite (WAL Mode)                   │  │
│                             │   ├─ Hash-Chained Transactions Block  │  │
│                             │   ├─ Circuit Breaker Automaton        │  │
│                             │   └─ Self-Healing JSON Snapshots      │  │
│                             └───────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🧠 Why Design-by-Contract (DbC)?

Traditional security relies on outer perimeter defenses (like WAFs or API gateways). If an attacker gets past the perimeter, internal code trusts everything.

**Design-by-Contract treats every function call like a legally binding contract:**

$$\text{Pre-Conditions} \longrightarrow \text{Pre-Invariant} \longrightarrow \text{Atomic Execution} \longrightarrow \text{Post-Invariant} \longrightarrow \text{Post-Conditions}$$

- **If the caller breaks the Pre-Condition:** The function refuses to run (`PreConditionError`).
- **If the database state was tampered with:** The Invariant fails, tripping the Circuit Breaker (`InvariantError`).
- **If a race condition destroys money:** The Post-Condition triggers an instant database rollback (`PostConditionError`).

---

## 🔄 The 4 Secure SDLC Phases

### 📋 Phase 1: Requirements Engineering (Misuse Cases)
Instead of only modeling what users *want* to do, we engineer for what attackers *try* to do:

| Legitimate Use Case | Attacker Misuse Case | Engineered Mitigation |
| :--- | :--- | :--- |
| **UC-1: Transfer Funds** | **MC-1: TOCTOU Race Condition** (5 simultaneous threads trying to overdraft balance) | `TRANSACTION_MUTEX` + SQLite `BEGIN EXCLUSIVE` lock + Post-condition check |
| **UC-2: Ledger Audit** | **MC-2: Insider Database Tampering** (Direct SQL UPDATE altering historical rows) | SHA-256 Hash-Chained Ledger + Automatic Circuit Breaker |
| **UC-3: Client Submission** | **MC-3: MITM Parameter Tampering** (Modifying payload amount from ₹100 to ₹4,500 in transit) | Constant-time HMAC-SHA256 payload signature verification |
| **UC-4: Balance Calculation** | **MC-4: Negative Amount Exploit** (Transferring `-₹5,000` to reverse subtraction math) | PC-2 Bounds Contract (`0 < amt <= 50,000`) + Conservation of Money Law |
| **UC-5: Network Retry** | **MC-5: Replay Attack** (Eavesdropping a signed request and resending it 10×) | Stateful Cryptographic Nonce Registry (consumed on first use) |
| **UC-6: Balance Query** | **MC-6: SQL Injection** (Injecting `' OR '1'='1` in fields) | Strict PC-1 schema types + parameterized SQLite bindings |

---

### 🗺️ Phase 2: Design & Threat Modeling (STRIDE + DREAD)
Every threat is evaluated across the system using the industry-standard **STRIDE** model and scored using **DREAD** metrics:

$$\text{DREAD Score} = \frac{\text{Damage} + \text{Reproducibility} + \text{Exploitability} + \text{Affected Users} + \text{Discoverability}}{5}$$

| STRIDE Category | Threat Scenario | DREAD Before SSE (v1.0) | DREAD After SSE (v2.0) | Mitigation Contract |
| :--- | :--- | :---: | :---: | :--- |
| **Spoofing** | MITM packet tampering / Replay | **8.5 / 10** | **1.2 / 10** | PC-4 Nonce + PC-5 HMAC-SHA256 |
| **Tampering** | Insider DB row manipulation | **9.0 / 10** | **1.4 / 10** | SHA-256 Ledger Chain + Circuit Breaker |
| **Repudiation** | Denying transaction authenticity | **7.5 / 10** | **1.0 / 10** | Cryptographic Hash Audit Trail |
| **Info Disclosure** | SQL injection parameter leaks | **6.0 / 10** | **2.0 / 10** | Parameterized SQL + PC-1 Schema |
| **Denial of Service** | TOCTOU parallel race condition | **8.0 / 10** | **1.5 / 10** | `TRANSACTION_MUTEX` Thread Serialization |
| **Elevation of Priv** | Negative value balance inversion | **9.5 / 10** | **1.0 / 10** | PC-2 Bounds + POST-1 Conservation |
| **AVERAGE** | **System-Wide Cumulative Risk** | **8.08 / 10** | **1.35 / 10** | **↓ 83.3% Overall Risk Reduction** |

---

### ⚙️ Phase 3: Defensive Implementation (`contracts.py` & `app.py`)
- **`contracts.py`:** Novel Design-by-Contract engine enforcing 6 Pre-conditions, Pre/Post Invariants, and 4 Post-conditions.
- **`app.py`:** Production Flask application with SQLite WAL mode, REST APIs, and 4 live Red-Team attack simulator endpoints.

---

### 🧪 Phase 4: Automated Verification (`test_sse_suite.py`)
Security is verified by **66 automated pytest assertions** executing in **0.63 seconds**:

| Test ID | Test Category | Tests | Vulnerability Checked | Result |
| :---: | :--- | :---: | :--- | :---: |
| **SR-01** | `TestSQLiResistance` | 4 | SQL injection in sender/receiver/amount fields | **PASSED** ✅ |
| **SR-02** | `TestNegativeAmountFuzzing` | 13 | Boundary testing: `-5000`, `0`, `50001`, overflow | **PASSED** ✅ |
| **SR-03** | `TestHMACTampering` | 11 | In-transit payload manipulation across all fields | **PASSED** ✅ |
| **SR-04** | `TestLedgerHashInvariant` | 9 | SHA-256 chain integrity, tampering, circuit breaker | **PASSED** ✅ |
| **SR-05** | `TestConcurrentThreadSafety` | 5 | 50 concurrent threads, race condition prevention | **PASSED** ✅ |
| **SR-06** | `TestNonceReplayDefense` | 5 | Anti-replay verification, duplicate token reuse | **PASSED** ✅ |
| **SR-07** | `TestConservationOfMoney` | 7 | Exact financial conservation: `Sb + Rb == Sa + Ra` | **PASSED** ✅ |
| **SR-08** | `TestCircuitBreaker` | 4 | Automaton state transitions: `CLOSED` ↔ `OPEN` | **PASSED** ✅ |
| **SR-09** | `TestSchemaValidation` | 4 | Missing parameters, incorrect datatypes | **PASSED** ✅ |
| **SR-10** | `TestRiskScoreEngine` | 4 | Context-aware fraud profiling & transaction velocity | **PASSED** ✅ |

---

## 🎯 Red-Team Attack Simulator

The built-in Red-Team console allows you to demonstrate real attacks with a single click. By toggling the **SDLC Mode** in the navbar, you can see the stark contrast between unengineered code and contract-driven code:

| Attack Scenario | What Attacker Does | v1.0 Naive (Unengineered) | v2.0 Secure SE (Contract-Driven) |
| :--- | :--- | :--- | :--- |
| **1. TOCTOU Race Condition** | Fires 5 simultaneous ₹2,000 transfers against a ₹5,000 balance | ❌ **VULNERABLE:** Race window opens. Balance drops to **-₹5,000** (Overdraft exploit succeeded). | ✅ **SECURE:** Mutex serializes execution. 2 pass (₹4,000), 3 are blocked. Balance safely remains **₹1,000**. |
| **2. Insider DB Tampering** | Executes raw SQL adding ₹99,000 directly into the database | ❌ **VULNERABLE:** Tampering is completely undetected. Rogue funds are kept. | ✅ **SECURE:** System invariant detects broken hash chain. **Circuit Breaker trips to OPEN** and freezes state. |
| **3. MITM Parameter Tamper** | Intercepts signed ₹100 transfer, changes amount to ₹4,500 | ❌ **VULNERABLE:** Server accepts modified amount. Attacker steals ₹4,500. | ✅ **SECURE:** PC-5 HMAC-SHA256 signature mismatch. Request is rejected immediately. |
| **4. Negative Amount Exploit** | Transfers `amount = -5000` to reverse deduction math | ❌ **VULNERABLE:** Math reverses: sender gains ₹5,000 and victim loses ₹5,000. | ✅ **SECURE:** PC-2 Bounds (`amount > 0`) and Conservation of Money law block the transfer. |

---

## 📊 Security Requirements Traceability Matrix (SRTM)

| Req ID | Security Requirement | STRIDE Threat | Design Contract Artifact | Implementation Module | Automated Test ID | Status |
| :---: | :--- | :---: | :--- | :--- | :--- | :---: |
| **SR-01** | Anti-Replay Protection | Spoofing | `PC-4: register_nonce()` | `contracts.py:108` | `TestNonceReplayDefense` | **VERIFIED** ✅ |
| **SR-02** | In-Transit Payload Integrity | Tampering | `PC-5: verify_hmac()` | `contracts.py:142` | `TestHMACTampering` | **VERIFIED** ✅ |
| **SR-03** | Historical Non-Repudiation | Tampering | SHA-256 Ledger Chain + Circuit | `contracts.py:210` | `TestLedgerHashInvariant` | **VERIFIED** ✅ |
| **SR-04** | Concurrency Race Immunity | DoS | `TRANSACTION_MUTEX` + `BEGIN EXCLUSIVE` | `contracts.py:465` | `TestConcurrentThreadSafety` | **VERIFIED** ✅ |
| **SR-05** | Conservation of Money Law | Elevation | `POST-1: check_postconditions()` | `contracts.py:410` | `TestConservationOfMoney` | **VERIFIED** ✅ |
| **SR-06** | SQL Injection Immunity | Info Disclosure | `PC-1: Schema` + Parameterized SQL | `app.py:85` | `TestSQLiResistance` | **VERIFIED** ✅ |

---

## 🛡️ Core Security Engineering Innovations

| Innovation | Formal Mechanism | Defends Against |
| :--- | :--- | :--- |
| **Pre-Condition Validation Pipeline** | Strict type bounds, positive amounts ( < x \le 50000$), context risk scoring ($< 70$) | Parameter injection, negative overdrafts, anomalous request bursts |
| **Cryptographic Hash-Chained Invariant** | Block hash linkage: $\\text{SHA256}(prev + sender + receiver + amt + ts)$ | Direct insider SQLite tampering, silent database modification |
| **Conservation of Money Law** | Mathematical post-condition: {before} + R_{before} == S_{after} + R_{after}$ | Algorithmic logic errors, currency generation or loss |
| **Anti-Replay Nonce Registry** | Ephemeral single-use cryptographic tokens | Network replay attacks, duplicate transaction resubmissions |
| **Constant-Time HMAC Payload Verification** | Secret-keyed SHA-256 HMAC checked with timing-safe comparison | Man-in-the-middle payload alteration |
| **Finite State Circuit Breaker** | Automaton states (CLOSED, OPEN, HALF_OPEN) with self-healing snapshot | System operation on corrupted state |

---

## 🔌 API Endpoints Reference

| Endpoint | Method | Role | Security Controls |
| :--- | :---: | :--- | :--- |
| /api/balances | GET | Retrieve account balances | Read-only parameterized query |
| /api/transfer | POST | Execute authenticated money transfer | Full @secure_contract pipeline |
| /api/ledger | GET | Audit cryptographic ledger chain | Invariant verification scanner |
| /api/circuit | GET | Check Circuit Breaker automaton state | Health telemetry monitoring |
| /api/attack/race | POST | Simulate 5-thread TOCTOU parallel overdraft | Mutex serialization & post-condition test |
| /api/attack/tamper | POST | Simulate direct SQL database manipulation | Hash-chain break detection |
| /api/self_heal | POST | Restore ledger from verified snapshot | Cryptographic state recovery |
| /api/attack/mitm | POST | Simulate modified payload in transit | HMAC-SHA256 integrity validation |
| /api/attack/negative| POST | Simulate inverted negative transfer | Bounded amount pre-condition check |
| /api/run_tests | POST | Run 66 automated pytest assertions | Subprocess test harness execution |
| /api/reset | POST | Reset demo state to genesis values | Clean test baseline restoration |

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.9 or higher
- Git

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/ShreyanshuRaj06/ZeroTrustPay.git

# 2. Navigate into the directory
cd ZeroTrustPay

# 3. Install lightweight dependencies (Flask & pytest only)
pip install -r requirements.txt

# 4. Start the application
python app.py
```

Now open your browser and navigate to: **[http://localhost:5000](http://localhost:5000)**

### Running Automated Security Tests

```bash
# Run full suite of 66 security tests
pytest test_sse_suite.py -v
```

---

## 📁 Project Structure

```
ZeroTrustPay/
├── app.py                                       # Flask backend + Red-Team endpoints + subprocess test runner
├── contracts.py                                 # Novel Design-by-Contract security engine (@secure_contract)
├── test_sse_suite.py                            # 66 automated pytest security verification tests
├── requirements.txt                             # Minimal dependencies (Flask, pytest)
├── README.md                                    # Comprehensive documentation
├── .gitignore                                   # Clean repository exclusions
└── templates/
    └── index.html                               # Minimalist obsidian-black UI workbench (Antigravity aesthetic)
```

---

## 📄 License

This project is distributed for educational and academic research evaluation.
