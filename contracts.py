"""
contracts.py — ZeroTrustPay Formal Design-by-Contract Security Engine
=======================================================================
Author  : Shreyanshu Raj
Module  : Secure Software Engineering (5th Semester)
Pattern : Design-by-Contract (DbC) with Cryptographic Invariants

This module implements a *novel* secure SE architecture:
  - @secure_contract decorator enforces Pre/Post-conditions + System Invariants
  - SHA-256 Hash-Chained Ledger Invariant (tamper-evident blockchain-style ledger)
  - Conservation of Money Post-Condition (formal financial law)
  - Circuit Breaker automaton (freezes mutations on invariant breach)
  - Nonce Registry (stateful anti-replay attack map)
  - Risk Scoring Engine (context-aware transaction risk profiler)

Design Principle: "Security is NOT an add-on; it is a provable property of the
system encoded in its formal contracts." — B. Meyer, Object-Oriented Software
Construction (adapted for FinTech Zero-Trust contexts)
"""

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Dict, Optional

# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL STATE MACHINES
# ─────────────────────────────────────────────────────────────────────────────

# Circuit Breaker states: CLOSED (normal) | OPEN (frozen) | HALF_OPEN (probe)
CIRCUIT_STATE = "CLOSED"
CIRCUIT_TRIP_REASON: Optional[str] = None
CIRCUIT_TRIPPED_AT: Optional[float] = None

# Nonce registry — prevents replay attacks; maps nonce -> ISO timestamp
_NONCE_REGISTRY: Dict[str, str] = {}
_NONCE_LOCK = threading.Lock()

# Telemetry log — ring buffer of last 200 contract events
_TELEMETRY: list = []
_TELEMETRY_LOCK = threading.Lock()
_MAX_TELEMETRY = 200

# Mutex for atomic financial transactions (prevents TOCTOU race conditions)
TRANSACTION_MUTEX = threading.Lock()

# Shared secret for HMAC-SHA256 payload signing (in production: HSM-backed)
HMAC_SECRET = b"ZeroTrustPay-HMAC-Secret-SSE-2024-Shreyanshu"

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

logger = logging.getLogger("contracts")
logger.setLevel(logging.DEBUG)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter(
    "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
))
logger.addHandler(_handler)


# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRY ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def _emit(level: str, phase: str, message: str, detail: Any = None) -> dict:
    """Append a contract event to the telemetry ring buffer and return it."""
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level,          # INFO | WARN | ERROR | CRITICAL
        "phase": phase,           # PRE | INV | POST | CIRCUIT
        "message": message,
        "detail": detail,
    }
    with _TELEMETRY_LOCK:
        _TELEMETRY.append(event)
        if len(_TELEMETRY) > _MAX_TELEMETRY:
            _TELEMETRY.pop(0)
    log_fn = {
        "INFO": logger.info,
        "WARN": logger.warning,
        "ERROR": logger.error,
        "CRITICAL": logger.critical,
    }.get(level, logger.debug)
    log_fn(f"[{phase}] {message}")
    return event


def get_telemetry(last_n: int = 50) -> list:
    """Return the last N telemetry events (thread-safe)."""
    with _TELEMETRY_LOCK:
        return list(_TELEMETRY[-last_n:])


def clear_telemetry():
    """Clear the telemetry log (used by demo reset)."""
    with _TELEMETRY_LOCK:
        _TELEMETRY.clear()


# ─────────────────────────────────────────────────────────────────────────────
# CIRCUIT BREAKER
# ─────────────────────────────────────────────────────────────────────────────

def trip_circuit(reason: str):
    """Transition Circuit Breaker to OPEN state — all mutations frozen."""
    global CIRCUIT_STATE, CIRCUIT_TRIP_REASON, CIRCUIT_TRIPPED_AT
    CIRCUIT_STATE = "OPEN"
    CIRCUIT_TRIP_REASON = reason
    CIRCUIT_TRIPPED_AT = time.time()
    _emit("CRITICAL", "CIRCUIT",
          f"⛔ Circuit Breaker TRIPPED: {reason}",
          {"state": "OPEN", "reason": reason})


def reset_circuit():
    """Manually reset Circuit Breaker to CLOSED (admin/self-heal action)."""
    global CIRCUIT_STATE, CIRCUIT_TRIP_REASON, CIRCUIT_TRIPPED_AT
    CIRCUIT_STATE = "CLOSED"
    CIRCUIT_TRIP_REASON = None
    CIRCUIT_TRIPPED_AT = None
    _emit("INFO", "CIRCUIT", "✅ Circuit Breaker RESET — system operational")


def get_circuit_status() -> dict:
    return {
        "state": CIRCUIT_STATE,
        "reason": CIRCUIT_TRIP_REASON,
        "tripped_at": CIRCUIT_TRIPPED_AT,
    }


# ─────────────────────────────────────────────────────────────────────────────
# NONCE REGISTRY (Anti-Replay)
# ─────────────────────────────────────────────────────────────────────────────

def register_nonce(nonce: str) -> bool:
    """
    Register a nonce. Returns True if novel (safe), False if replayed (blocked).
    Thread-safe via dedicated lock.
    """
    with _NONCE_LOCK:
        if nonce in _NONCE_REGISTRY:
            return False  # Replay detected
        _NONCE_REGISTRY[nonce] = datetime.now(timezone.utc).isoformat()
        return True


def clear_nonces():
    """Clear nonce registry (used by demo reset)."""
    with _NONCE_LOCK:
        _NONCE_REGISTRY.clear()


def get_nonce_count() -> int:
    with _NONCE_LOCK:
        return len(_NONCE_REGISTRY)


# ─────────────────────────────────────────────────────────────────────────────
# HMAC-SHA256 PAYLOAD INTEGRITY
# ─────────────────────────────────────────────────────────────────────────────

def compute_hmac(payload: dict) -> str:
    """
    Compute HMAC-SHA256 over a canonical JSON representation of the payload.
    Fields included: sender, receiver, amount, nonce (order-independent via sort).
    """
    canonical = json.dumps(
        {k: payload[k] for k in sorted(payload.keys()) if k != "signature"},
        sort_keys=True
    )
    return hmac.new(HMAC_SECRET, canonical.encode(), hashlib.sha256).hexdigest()


def verify_hmac(payload: dict, provided_sig: str) -> bool:
    """Constant-time HMAC comparison (immune to timing attacks)."""
    expected = compute_hmac(payload)
    return hmac.compare_digest(expected, provided_sig)


# ─────────────────────────────────────────────────────────────────────────────
# RISK SCORING ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def compute_risk_score(payload: dict, sender_balance: float) -> float:
    """
    Context-Aware Risk Score (0–100). Score >= 70 triggers pre-condition failure.

    Scoring factors:
      - Amount vs. balance ratio     (0–40 pts)
      - Transfer amount absolute     (0–20 pts)
      - Velocity: nonce pool size    (0–20 pts)
      - Cross-midnight timestamp     (0–10 pts)
      - Even-round "structuring" amount (0–10 pts)
    """
    score = 0.0
    amount = float(payload.get("amount", 0))

    # Factor 1: Amount/Balance ratio
    if sender_balance > 0:
        ratio = amount / sender_balance
        score += min(40.0, ratio * 40.0)
    else:
        score += 40.0  # No balance = max risk

    # Factor 2: Absolute amount
    if amount > 40000:
        score += 20.0
    elif amount > 20000:
        score += 10.0
    elif amount > 10000:
        score += 5.0

    # Factor 3: Nonce pool velocity (many nonces = many recent transactions)
    nonces = get_nonce_count()
    score += min(20.0, nonces * 0.5)

    # Factor 4: Late-night transaction (22:00–05:00 UTC)
    hour = datetime.now(timezone.utc).hour
    if hour >= 22 or hour < 5:
        score += 10.0

    # Factor 5: "Structuring" — suspiciously round amounts
    if amount > 0 and amount % 10000 == 0:
        score += 10.0

    return round(min(100.0, score), 2)


# ─────────────────────────────────────────────────────────────────────────────
# LEDGER HASH FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def compute_ledger_hash(prev_hash: str, sender: str, receiver: str,
                        amount: float, timestamp: str) -> str:
    """
    Compute SHA-256 block hash for the hash-chained ledger.
    Formula: SHA256(prev_hash || sender || receiver || str(amount) || timestamp)
    This creates a Merkle-like chain where ANY mutation to a historical row
    cascades as a detectable hash mismatch in all subsequent rows.
    """
    raw = f"{prev_hash}{sender}{receiver}{amount:.6f}{timestamp}"
    return hashlib.sha256(raw.encode()).hexdigest()


def verify_ledger_chain(db_path: str) -> dict:
    """
    Full ledger chain integrity verification.

    Reads every row from the transactions table in order and re-computes
    the hash chain from scratch. Returns:
      {
        "valid": bool,
        "total_rows": int,
        "corrupted_rows": [row_ids],
        "detail": str
      }

    If ANY row's stored hash != recomputed hash, the invariant is broken.
    The function stops short-circuit at the first bad block to preserve the
    "crime scene" but continues to find ALL corrupted rows.
    """
    corrupted = []
    total = 0

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""
            SELECT id, sender, receiver, amount, timestamp,
                   prev_hash, curr_hash
            FROM transactions
            ORDER BY id ASC
        """)
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        return {
            "valid": False,
            "total_rows": 0,
            "corrupted_rows": [],
            "detail": f"DB read error: {e}"
        }

    expected_prev = "GENESIS"
    for row in rows:
        total += 1
        recomputed = compute_ledger_hash(
            expected_prev,
            row["sender"],
            row["receiver"],
            float(row["amount"]),
            row["timestamp"]
        )
        stored = row["curr_hash"]

        if recomputed != stored:
            corrupted.append({
                "id": row["id"],
                "stored_hash": stored[:16] + "...",
                "expected_hash": recomputed[:16] + "...",
                "sender": row["sender"],
                "receiver": row["receiver"],
                "amount": row["amount"],
            })
            # Even if corrupted, advance the chain so we find all broken rows
            # (we do NOT use the corrupted row's hash as next prev_hash)
            expected_prev = recomputed  # Use what it SHOULD have been
        else:
            expected_prev = stored

    is_valid = len(corrupted) == 0
    detail = "✅ All blocks verified — ledger integrity intact" if is_valid else \
             f"⛔ TAMPERED! {len(corrupted)} block(s) have broken hash chains"

    _emit(
        "INFO" if is_valid else "CRITICAL",
        "INV",
        detail,
        {"total": total, "corrupted": len(corrupted)}
    )
    return {
        "valid": is_valid,
        "total_rows": total,
        "corrupted_rows": corrupted,
        "detail": detail
    }


# ─────────────────────────────────────────────────────────────────────────────
# PRE-CONDITION CONTRACT
# ─────────────────────────────────────────────────────────────────────────────

class PreConditionError(Exception):
    """Raised when a transaction violates a pre-condition contract."""


def check_preconditions(payload: dict, sender_balance: float,
                        secure_mode: bool = True) -> dict:
    """
    Evaluate all pre-condition contracts for a financial transaction.

    Pre-conditions checked (in order):
      PC-1: Schema — required fields present and correct types
      PC-2: Amount bounds — 0 < amount <= 50,000
      PC-3: Self-transfer — sender != receiver
      PC-4: Nonce uniqueness — anti-replay
      PC-5: HMAC-SHA256 signature integrity
      PC-6: Risk score < 70

    In 'naive' (v1.0) mode, only basic bounds are checked.
    In 'secure' (v2.0) mode, all 6 contracts are enforced.

    Returns: {"passed": bool, "violations": list[str]}
    """
    violations = []

    if not secure_mode:
        # v1.0 Naive: minimal validation — no HMAC, no nonce, no risk score
        amount = payload.get("amount", 0)
        # Even naive mode won't check for negative — that's the exploit
        if not isinstance(amount, (int, float)):
            violations.append("PC-1 [Schema]: amount must be numeric")
        _emit("WARN", "PRE",
              "v1.0 NAIVE mode: Minimal pre-conditions only (INSECURE)",
              {"checks": "basic-only"})
        return {"passed": len(violations) == 0, "violations": violations}

    # ── PC-1: Schema Validation ───────────────────────────────────────────
    required = {
        "sender": str, "receiver": str,
        "amount": (int, float), "nonce": str, "signature": str
    }
    for field, ftype in required.items():
        if field not in payload:
            violations.append(f"PC-1 [Schema]: Missing required field '{field}'")
        elif not isinstance(payload[field], ftype):
            type_name = (
                " or ".join(t.__name__ for t in ftype)
                if isinstance(ftype, tuple) else ftype.__name__
            )
            violations.append(
                f"PC-1 [Schema]: Field '{field}' must be {type_name}, "
                f"got {type(payload[field]).__name__}"
            )

    if violations:
        _emit("ERROR", "PRE", "PC-1 Schema violation", violations)
        return {"passed": False, "violations": violations}

    amount = float(payload["amount"])
    sender = payload["sender"]
    receiver = payload["receiver"]

    # ── PC-2: Amount Bounds ───────────────────────────────────────────────
    if amount <= 0:
        violations.append(
            f"PC-2 [Amount Bounds]: amount={amount} ≤ 0 — "
            "Negative/zero transfer blocked (prevents balance-reversal exploit)"
        )
    elif amount > 50000:
        violations.append(
            f"PC-2 [Amount Bounds]: amount={amount} > 50,000 — "
            "Exceeds single-transaction limit"
        )

    # ── PC-3: Self-Transfer ───────────────────────────────────────────────
    if sender == receiver:
        violations.append(
            f"PC-3 [Self-Transfer]: sender=receiver='{sender}' — "
            "Self-transfers are disallowed"
        )

    # ── PC-4: Nonce Uniqueness (Anti-Replay) ─────────────────────────────
    nonce = payload["nonce"]
    if not register_nonce(nonce):
        violations.append(
            f"PC-4 [Nonce]: Nonce '{nonce[:12]}...' already consumed — "
            "REPLAY ATTACK DETECTED"
        )

    # ── PC-5: HMAC-SHA256 Signature Integrity ────────────────────────────
    if not verify_hmac(payload, payload["signature"]):
        violations.append(
            "PC-5 [HMAC]: Payload signature mismatch — "
            "MITM parameter tampering detected (amount or fields altered in-transit)"
        )

    # ── PC-6: Risk Score ─────────────────────────────────────────────────
    risk = compute_risk_score(payload, sender_balance)
    if risk >= 70:
        violations.append(
            f"PC-6 [Risk]: Risk score {risk}/100 ≥ 70 — "
            "Transaction flagged as high-risk; requires manual review"
        )

    passed = len(violations) == 0
    level = "INFO" if passed else "ERROR"
    _emit(level, "PRE",
          "✅ All pre-conditions satisfied" if passed
          else f"❌ {len(violations)} pre-condition violation(s)",
          {
              "amount": amount,
              "sender": sender,
              "receiver": receiver,
              "risk_score": risk if secure_mode else "N/A",
              "violations": violations
          })

    return {"passed": passed, "violations": violations, "risk_score": risk}


# ─────────────────────────────────────────────────────────────────────────────
# POST-CONDITION CONTRACT (Conservation of Money Law)
# ─────────────────────────────────────────────────────────────────────────────

class PostConditionError(Exception):
    """Raised when a transaction violates the Conservation of Money law."""


def check_postconditions(sender_before: float, receiver_before: float,
                         sender_after: float, receiver_after: float,
                         amount: float, secure_mode: bool = True) -> dict:
    """
    Enforce the Conservation of Money Post-Condition:

      LAW: (Sb + Rb) == (Sa + Ra)      ← Total money is conserved
      LAW: Sa >= 0                       ← No overdraft
      LAW: Sa == Sb - amount             ← Sender debited exactly
      LAW: Ra == Rb + amount             ← Receiver credited exactly

    In v1.0 (naive) mode, these are NOT checked → exploits succeed.
    In v2.0 (secure) mode, any violation triggers automatic rollback.
    """
    violations = []

    if not secure_mode:
        _emit("WARN", "POST",
              "v1.0 NAIVE mode: Conservation of Money NOT enforced (INSECURE)",
              {"result": "unchecked"})
        return {"passed": True, "violations": [], "naive": True}

    total_before = round(sender_before + receiver_before, 6)
    total_after = round(sender_after + receiver_after, 6)

    # Conservation of Money
    if abs(total_before - total_after) > 0.001:
        violations.append(
            f"POST-1 [Conservation]: "
            f"Total before={total_before:.2f} ≠ Total after={total_after:.2f}. "
            f"Money created/destroyed (Δ = {total_after - total_before:.2f}). "
            "TRANSACTION ROLLED BACK."
        )

    # No overdraft
    if sender_after < 0:
        violations.append(
            f"POST-2 [No Overdraft]: "
            f"Sender balance after={sender_after:.2f} < 0. "
            "Overdraft would violate financial invariant. ROLLED BACK."
        )

    # Exact debit check
    expected_sender_after = round(sender_before - amount, 6)
    if abs(sender_after - expected_sender_after) > 0.001:
        violations.append(
            f"POST-3 [Debit Integrity]: "
            f"Expected sender_after={expected_sender_after:.2f}, "
            f"got {sender_after:.2f}. Race condition or manipulation detected."
        )

    # Exact credit check
    expected_receiver_after = round(receiver_before + amount, 6)
    if abs(receiver_after - expected_receiver_after) > 0.001:
        violations.append(
            f"POST-4 [Credit Integrity]: "
            f"Expected receiver_after={expected_receiver_after:.2f}, "
            f"got {receiver_after:.2f}. Race condition or manipulation detected."
        )

    passed = len(violations) == 0
    _emit(
        "INFO" if passed else "CRITICAL",
        "POST",
        "✅ Conservation of Money verified" if passed
        else f"❌ CRITICAL: {len(violations)} post-condition violation(s) — ROLLBACK",
        {
            "sender_before": sender_before,
            "receiver_before": receiver_before,
            "sender_after": sender_after,
            "receiver_after": receiver_after,
            "amount": amount,
            "violations": violations
        }
    )

    return {"passed": passed, "violations": violations}


# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM INVARIANT CONTRACT (Hash-Chained Ledger)
# ─────────────────────────────────────────────────────────────────────────────

class InvariantError(Exception):
    """Raised when the system invariant (ledger hash chain) is broken."""


def check_invariant(db_path: str, secure_mode: bool = True) -> dict:
    """
    Verify the System Invariant: Cryptographic Hash-Chained Ledger Integrity.

    Before AND after every transaction, the entire ledger is re-verified.
    If ANY historical row was tampered with (SQL injection, insider attack,
    direct DB edit), the hash chain breaks and the Circuit Breaker trips.

    In v1.0 (naive) mode, this check is SKIPPED → tampering goes undetected.
    """
    if not secure_mode:
        _emit("WARN", "INV",
              "v1.0 NAIVE mode: Ledger invariant NOT checked (INSECURE)")
        return {"passed": True, "naive": True, "result": {}}

    # Circuit Breaker short-circuit — if already OPEN, block all mutations
    if CIRCUIT_STATE == "OPEN":
        _emit("CRITICAL", "INV",
              f"⛔ Circuit Breaker OPEN — mutation blocked. Reason: {CIRCUIT_TRIP_REASON}")
        return {
            "passed": False,
            "circuit_open": True,
            "reason": CIRCUIT_TRIP_REASON
        }

    result = verify_ledger_chain(db_path)

    if not result["valid"]:
        # Invariant broken — trip Circuit Breaker
        reason = (
            f"Hash chain broken at {len(result['corrupted_rows'])} row(s). "
            f"Possible insider DB tampering or SQL injection."
        )
        trip_circuit(reason)
        return {
            "passed": False,
            "circuit_open": True,
            "reason": reason,
            "corrupted_rows": result["corrupted_rows"],
            "result": result
        }

    return {
        "passed": True,
        "total_rows": result["total_rows"],
        "result": result
    }


# ─────────────────────────────────────────────────────────────────────────────
# @secure_contract DECORATOR — The Unified Contract Wrapper
# ─────────────────────────────────────────────────────────────────────────────

def secure_contract(db_path_getter: Callable, secure_mode_getter: Callable):
    """
    Factory that returns the @secure_contract decorator.

    The decorated function MUST accept `payload: dict` as first arg and
    return a dict with at least `{"sender_after": float, "receiver_after": float}`.

    Contract Execution Order:
      1. PRE-CONDITION  : Validate payload before ANY state change
      2. PRE-INVARIANT  : Verify ledger hash chain is intact (before mutation)
      3. FUNCTION BODY  : Execute the atomic financial operation (under mutex)
      4. POST-INVARIANT : Re-verify ledger hash chain (after mutation)
      5. POST-CONDITION : Verify Conservation of Money law

    Any violation at any stage raises the appropriate contract exception and
    prevents/rolls back state changes.

    Args:
        db_path_getter: Callable() -> str  — returns path to SQLite DB
        secure_mode_getter: Callable() -> bool — returns current mode flag
    """
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(payload: dict, sender_balance: float,
                    receiver_balance: float, *args, **kwargs):

            secure = secure_mode_getter()
            db = db_path_getter()

            if secure:
                acquired = TRANSACTION_MUTEX.acquire(timeout=5.0)
                if not acquired:
                    raise PreConditionError(
                        "PC-MUTEX: Could not acquire transaction lock — "
                        "another transaction in progress. TOCTOU protection active."
                    )

            try:
                # Under mutex in secure mode: refresh committed balances from DB if available
                if secure and db and os.path.exists(db):
                    try:
                        conn_chk = sqlite3.connect(db, timeout=2.0)
                        c_chk = conn_chk.cursor()
                        c_chk.execute("SELECT balance FROM wallets WHERE username = ?", (payload.get("sender"),))
                        r_s = c_chk.fetchone()
                        if r_s is not None:
                            sender_balance = float(r_s[0])
                        c_chk.execute("SELECT balance FROM wallets WHERE username = ?", (payload.get("receiver"),))
                        r_r = c_chk.fetchone()
                        if r_r is not None:
                            receiver_balance = float(r_r[0])
                        conn_chk.close()
                    except Exception:
                        pass

                _emit("INFO", "PRE",
                      f"🔐 @secure_contract invoked for {payload.get('sender')} → "
                      f"{payload.get('receiver')} | ₹{payload.get('amount')} | "
                      f"Mode: {'v2.0 Secure' if secure else 'v1.0 Naive'}",
                      {"mode": "secure" if secure else "naive"})

                # ── STAGE 1: PRE-CONDITIONS ───────────────────────────────────
                pre_result = check_preconditions(payload, sender_balance, secure)
                if not pre_result["passed"]:
                    raise PreConditionError(
                        f"Pre-condition failed: {'; '.join(pre_result['violations'])}"
                    )

                # ── STAGE 2: PRE-INVARIANT ────────────────────────────────────
                inv_pre = check_invariant(db, secure)
                if not inv_pre["passed"]:
                    raise InvariantError(
                        f"Pre-invariant failed (hash chain broken): "
                        f"{inv_pre.get('reason', 'Unknown')}"
                    )

                # ── STAGE 3: FUNCTION BODY ────────────────────────────────────
                result = fn(payload, sender_balance, receiver_balance,
                            *args, **kwargs)

                # ── STAGE 4: POST-INVARIANT ───────────────────────────────────
                inv_post = check_invariant(db, secure)
                if not inv_post["passed"]:
                    raise InvariantError(
                        f"Post-invariant failed — ledger corrupted after write: "
                        f"{inv_post.get('reason', 'Unknown')}"
                    )

                # ── STAGE 5: POST-CONDITIONS ──────────────────────────────────
                post_result = check_postconditions(
                    sender_before=sender_balance,
                    receiver_before=receiver_balance,
                    sender_after=result.get("sender_after", sender_balance),
                    receiver_after=result.get("receiver_after", receiver_balance),
                    amount=float(payload.get("amount", 0)),
                    secure_mode=secure
                )

                if not post_result["passed"]:
                    # POST-condition violation → trigger rollback via exception
                    raise PostConditionError(
                        f"Post-condition violated (Conservation of Money broken): "
                        f"{'; '.join(post_result['violations'])}"
                    )

                _emit("INFO", "POST",
                      f"✅ Transaction contract FULFILLED: "
                      f"₹{payload.get('amount')} {payload.get('sender')} → "
                      f"{payload.get('receiver')}",
                      {
                          "sender_after": result.get("sender_after"),
                          "receiver_after": result.get("receiver_after")
                      })

                result["contract_telemetry"] = {
                    "pre": pre_result,
                    "inv_pre": inv_pre,
                    "inv_post": inv_post,
                    "post": post_result,
                }
                return result

            finally:
                if secure:
                    TRANSACTION_MUTEX.release()

        return wrapper
    return decorator
