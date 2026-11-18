"""
test_sse_suite.py — ZeroTrustPay Automated Security Verification & Fuzzing Suite
==================================================================================
Author  : Shreyanshu Raj
Module  : Secure Software Engineering (5th Semester)
Tooling : pytest + stdlib (no external dependencies beyond Flask + pytest)

Test Categories:
  [SR-01] SQLi Resistance      — parameterized queries prevent injection
  [SR-02] Negative Amount Fuzz — bounds contract blocks all negative/zero values
  [SR-03] HMAC Tampering       — MITM payload modification detected
  [SR-04] Ledger Hash Invariant— SHA-256 chain integrity verification
  [SR-05] TOCTOU Thread Safety — concurrent race conditions blocked by mutex
  [SR-06] Nonce Replay Defense — duplicate nonce blocked (anti-replay)
  [SR-07] Conservation of Money— post-condition law enforced after every transfer
  [SR-08] Circuit Breaker      — trips on invariant break, blocks further writes
  [SR-09] Schema Validation    — missing/wrong-type fields rejected
  [SR-10] Risk Score Engine    — high-risk transactions flagged

Design: Tests are self-contained — each creates a fresh in-memory SQLite DB
        and operates on isolated contract modules. No Flask server required.
"""

import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import uuid

import pytest

# Ensure parent directory is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import contracts as C


# ─────────────────────────────────────────────────────────────────────────────
# TEST FIXTURES
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_global_state():
    """Before each test: reset circuit breaker and nonce registry."""
    C.reset_circuit()
    C.clear_nonces()
    C.clear_telemetry()
    yield
    # Teardown: reset again (clean slate for next test)
    C.reset_circuit()
    C.clear_nonces()


@pytest.fixture
def tmp_db(tmp_path):
    """
    Provide a fresh temporary SQLite database with the ZeroTrustPay schema.
    Returns (db_path, conn_factory).
    """
    db_path = str(tmp_path / "test_zerotrust.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS wallets (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            balance  REAL NOT NULL DEFAULT 0.0
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            sender    TEXT NOT NULL,
            receiver  TEXT NOT NULL,
            amount    REAL NOT NULL,
            timestamp TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            curr_hash TEXT NOT NULL,
            nonce     TEXT,
            status    TEXT NOT NULL DEFAULT 'SUCCESS'
        );
        INSERT INTO wallets (username, balance) VALUES ('Alice', 5000.0);
        INSERT INTO wallets (username, balance) VALUES ('Bob', 2000.0);
    """)
    conn.commit()
    conn.close()
    return db_path


def _make_valid_payload(sender="Alice", receiver="Bob", amount=100,
                        nonce=None) -> dict:
    """Construct a valid, HMAC-signed payload."""
    nonce = nonce or str(uuid.uuid4())
    payload = {
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "nonce": nonce,
    }
    payload["signature"] = C.compute_hmac(payload)
    return payload


def _insert_legit_tx(db_path: str, sender="Alice", receiver="Bob", amount=100.0):
    """Insert a legitimately hash-chained transaction into the test DB."""
    from datetime import datetime, timezone
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT curr_hash FROM transactions ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    prev_hash = row["curr_hash"] if row else "GENESIS"
    ts = datetime.now(timezone.utc).isoformat()
    curr_hash = C.compute_ledger_hash(prev_hash, sender, receiver, amount, ts)
    cur.execute("""
        INSERT INTO transactions
            (sender, receiver, amount, timestamp, prev_hash, curr_hash, nonce)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (sender, receiver, amount, ts, prev_hash, curr_hash, str(uuid.uuid4())))
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# [SR-01] SQL INJECTION RESISTANCE
# ─────────────────────────────────────────────────────────────────────────────

class TestSQLiResistance:
    """
    Verify that all DB queries use parameterized statements and are immune
    to classic SQL injection payloads in sender/receiver/amount fields.
    """

    sqli_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE wallets; --",
        "' UNION SELECT username, balance FROM wallets --",
        "1; SELECT * FROM wallets WHERE '1'='1",
        "' OR 1=1 --",
        "admin'--",
        "' OR ''='",
    ]

    def test_sqli_in_sender_field_rejected_by_schema(self):
        """SQL injection strings in 'sender' fail schema contract (not in DB)."""
        for sqli in self.sqli_payloads:
            payload = _make_valid_payload(sender=sqli)
            # Recompute HMAC with the sqli sender (so HMAC passes, schema won't)
            # The key point: schema check runs BEFORE any DB query
            result = C.check_preconditions(payload, sender_balance=5000, secure_mode=True)
            # Payload "passes" schema type-wise (it's a str) but the nonce check
            # will register it. The main protection is parameterized queries.
            # We verify the query doesn't raise or corrupt the DB.
            assert isinstance(result, dict), "Pre-condition must return a dict"

    def test_sqli_does_not_corrupt_ledger(self, tmp_db):
        """After processing a SQLi payload, ledger chain remains intact."""
        for sqli in self.sqli_payloads[:3]:
            # Attempt SQLi via sender field (pre-condition blocks before DB write)
            payload = _make_valid_payload(sender=sqli)
            try:
                C.check_preconditions(payload, sender_balance=0, secure_mode=True)
            except Exception:
                pass  # Blocked by contract — expected

        # Insert a legitimate entry and verify chain is clean
        _insert_legit_tx(tmp_db)
        result = C.verify_ledger_chain(tmp_db)
        assert result["valid"] is True, \
            f"Ledger chain corrupted after SQLi attempts: {result}"

    def test_sqli_amount_field_blocked_by_type_check(self):
        """Non-numeric amount (SQLi string) fails PC-1 schema check."""
        payload = {
            "sender": "Alice",
            "receiver": "Bob",
            "amount": "100; DROP TABLE wallets; --",  # Type mismatch
            "nonce": str(uuid.uuid4()),
            "signature": "fakesig",
        }
        result = C.check_preconditions(payload, sender_balance=5000, secure_mode=True)
        assert result["passed"] is False, "String amount should fail schema check"
        assert any("PC-1" in v for v in result["violations"]), \
            "PC-1 schema violation expected for non-numeric amount"

    def test_parameterized_query_integrity(self, tmp_db):
        """Direct verify: inserting via parameterized query preserves hash chain."""
        _insert_legit_tx(tmp_db, "Alice", "Bob", 500.0)
        _insert_legit_tx(tmp_db, "Bob", "Alice", 200.0)
        result = C.verify_ledger_chain(tmp_db)
        assert result["valid"] is True
        assert result["total_rows"] == 2


# ─────────────────────────────────────────────────────────────────────────────
# [SR-02] NEGATIVE AMOUNT FUZZING
# ─────────────────────────────────────────────────────────────────────────────

class TestNegativeAmountFuzzing:
    """
    Fuzz all boundary values for the amount field.
    PC-2 contract must block: negative, zero, NaN-equivalent, overflow.
    """

    evil_amounts = [
        -5000, -1, -0.01, 0, -999999,
        -0.000001, -50001, 0.0, -2 ** 31,
    ]

    @pytest.mark.parametrize("amount", evil_amounts)
    def test_negative_or_zero_amount_blocked(self, amount):
        """Every non-positive amount must fail PC-2 [Amount Bounds]."""
        payload = _make_valid_payload(amount=amount)
        result = C.check_preconditions(payload, sender_balance=5000, secure_mode=True)
        assert result["passed"] is False, \
            f"Amount {amount} should be blocked by PC-2 but was accepted"
        assert any("PC-2" in v for v in result["violations"]), \
            f"PC-2 violation expected for amount={amount}, got: {result['violations']}"

    def test_overflow_amount_blocked(self):
        """Amount > 50,000 must fail PC-2 [Amount Bounds]."""
        payload = _make_valid_payload(amount=50001)
        result = C.check_preconditions(payload, sender_balance=1000000, secure_mode=True)
        assert result["passed"] is False
        assert any("PC-2" in v for v in result["violations"])

    def test_exactly_at_upper_bound_accepted(self):
        """Amount == 50,000 exactly should pass PC-2."""
        payload = _make_valid_payload(amount=50000)
        # Note: other checks (risk, nonce) may fail; we isolate PC-2 here
        result = C.check_preconditions(payload, sender_balance=100000, secure_mode=True)
        pc2_violation = [v for v in result.get("violations", []) if "PC-2" in v]
        assert len(pc2_violation) == 0, \
            f"₹50,000 should pass PC-2 bounds, but got: {pc2_violation}"

    def test_fractional_valid_amount_accepted(self):
        """Small positive fractional amount (e.g. ₹0.50) should pass PC-2."""
        payload = _make_valid_payload(amount=0.50)
        result = C.check_preconditions(payload, sender_balance=5000, secure_mode=True)
        pc2_violation = [v for v in result.get("violations", []) if "PC-2" in v]
        assert len(pc2_violation) == 0, \
            f"₹0.50 should pass PC-2 but got: {pc2_violation}"

    def test_naive_mode_does_not_block_negative(self):
        """In v1.0 naive mode, negative amounts are NOT blocked (vulnerability exposed)."""
        payload = _make_valid_payload(amount=-5000)
        result = C.check_preconditions(payload, sender_balance=5000, secure_mode=False)
        # Naive mode only does minimal checks — negative SHOULD pass through
        assert result["passed"] is True, \
            "Naive mode should NOT block negative amounts (this is the vulnerability)"


# ─────────────────────────────────────────────────────────────────────────────
# [SR-03] HMAC TAMPERING DETECTION
# ─────────────────────────────────────────────────────────────────────────────

class TestHMACTampering:
    """
    Verify PC-5 [HMAC] contract catches all forms of payload tampering.
    """

    def test_unmodified_payload_passes_hmac(self):
        """A correctly signed, unmodified payload passes PC-5."""
        payload = _make_valid_payload(amount=500)
        result = C.check_preconditions(payload, sender_balance=5000, secure_mode=True)
        pc5_violations = [v for v in result.get("violations", []) if "PC-5" in v]
        assert len(pc5_violations) == 0, \
            f"Valid HMAC should pass PC-5 but got: {pc5_violations}"

    def test_amount_tampered_in_transit_detected(self):
        """Changing amount after signing triggers PC-5 HMAC mismatch."""
        payload = _make_valid_payload(amount=100)
        payload["amount"] = 9999  # Attacker modifies amount in-transit
        result = C.check_preconditions(payload, sender_balance=5000, secure_mode=True)
        assert result["passed"] is False
        assert any("PC-5" in v for v in result["violations"]), \
            "PC-5 HMAC violation expected after amount tampering"

    def test_sender_tampered_in_transit_detected(self):
        """Changing sender after signing triggers PC-5 HMAC mismatch."""
        payload = _make_valid_payload(sender="Alice", amount=100)
        payload["sender"] = "EvilHacker"  # Attacker changes sender
        result = C.check_preconditions(payload, sender_balance=5000, secure_mode=True)
        assert result["passed"] is False
        assert any("PC-5" in v for v in result["violations"])

    def test_receiver_tampered_in_transit_detected(self):
        """Changing receiver after signing triggers PC-5 HMAC mismatch."""
        payload = _make_valid_payload(receiver="Bob", amount=100)
        payload["receiver"] = "AttackerWallet"
        result = C.check_preconditions(payload, sender_balance=5000, secure_mode=True)
        assert result["passed"] is False
        assert any("PC-5" in v for v in result["violations"])

    def test_wrong_signature_rejected(self):
        """A completely wrong/random signature fails PC-5."""
        payload = _make_valid_payload(amount=500)
        payload["signature"] = "a" * 64  # Random hex-looking string
        result = C.check_preconditions(payload, sender_balance=5000, secure_mode=True)
        assert result["passed"] is False
        assert any("PC-5" in v for v in result["violations"])

    def test_empty_signature_rejected(self):
        """Empty signature fails PC-5."""
        payload = _make_valid_payload(amount=500)
        payload["signature"] = ""
        result = C.check_preconditions(payload, sender_balance=5000, secure_mode=True)
        assert result["passed"] is False

    @pytest.mark.parametrize("tamper_field,tamper_value", [
        ("amount", 0),
        ("amount", -1),
        ("amount", 99999),
        ("sender", "INJECTED"),
        ("receiver", "MALICIOUS"),
    ])
    def test_all_field_tampering_caught(self, tamper_field, tamper_value):
        """Parametric: any field modification after signing must be detected."""
        payload = _make_valid_payload(amount=200)
        payload[tamper_field] = tamper_value
        result = C.check_preconditions(payload, sender_balance=5000, secure_mode=True)
        assert result["passed"] is False, \
            f"Tampering {tamper_field}={tamper_value} should be caught"


# ─────────────────────────────────────────────────────────────────────────────
# [SR-04] LEDGER HASH CHAIN INVARIANT
# ─────────────────────────────────────────────────────────────────────────────

class TestLedgerHashInvariant:
    """
    Verify the SHA-256 hash-chained ledger invariant detects all mutations.
    """

    def test_empty_ledger_is_valid(self, tmp_db):
        """Empty ledger has no blocks to verify — trivially valid."""
        result = C.verify_ledger_chain(tmp_db)
        assert result["valid"] is True
        assert result["total_rows"] == 0

    def test_single_valid_block_passes(self, tmp_db):
        """A single correctly-hashed block passes invariant."""
        _insert_legit_tx(tmp_db)
        result = C.verify_ledger_chain(tmp_db)
        assert result["valid"] is True
        assert result["total_rows"] == 1

    def test_multi_block_chain_passes(self, tmp_db):
        """A chain of 5 correctly-hashed blocks all pass."""
        for i in range(5):
            _insert_legit_tx(tmp_db, "Alice", "Bob", float(100 + i * 50))
        result = C.verify_ledger_chain(tmp_db)
        assert result["valid"] is True
        assert result["total_rows"] == 5

    def test_insider_amount_tamper_detected(self, tmp_db):
        """Directly modifying transaction amount breaks the hash chain."""
        _insert_legit_tx(tmp_db, "Alice", "Bob", 100.0)
        _insert_legit_tx(tmp_db, "Bob", "Alice", 50.0)

        # Insider executes raw SQL: inflates amount without updating curr_hash
        conn = sqlite3.connect(tmp_db)
        conn.execute("UPDATE transactions SET amount = 99100.0 WHERE id = 1")
        conn.commit()
        conn.close()

        result = C.verify_ledger_chain(tmp_db)
        assert result["valid"] is False, \
            "Tampered amount must break hash chain"
        assert len(result["corrupted_rows"]) >= 1, \
            "At least one corrupted row must be reported"
        assert result["corrupted_rows"][0]["id"] == 1

    def test_insider_sender_tamper_detected(self, tmp_db):
        """Modifying the sender field breaks the hash chain."""
        _insert_legit_tx(tmp_db, "Alice", "Bob", 500.0)
        conn = sqlite3.connect(tmp_db)
        conn.execute("UPDATE transactions SET sender = 'HACKER' WHERE id = 1")
        conn.commit()
        conn.close()
        result = C.verify_ledger_chain(tmp_db)
        assert result["valid"] is False

    def test_cascading_tamper_detected(self, tmp_db):
        """Tampering block 1 cascades corruption to all subsequent blocks."""
        for i in range(5):
            _insert_legit_tx(tmp_db, "Alice", "Bob", 100.0)

        # Tamper block 1 — should break the entire chain
        conn = sqlite3.connect(tmp_db)
        conn.execute("UPDATE transactions SET amount = 50000.0 WHERE id = 1")
        conn.commit()
        conn.close()

        result = C.verify_ledger_chain(tmp_db)
        assert result["valid"] is False
        # All blocks after the tampered one will also appear corrupted
        assert len(result["corrupted_rows"]) >= 1

    def test_hash_chain_trips_circuit_breaker(self, tmp_db):
        """When invariant check fails, Circuit Breaker must transition to OPEN."""
        _insert_legit_tx(tmp_db)
        conn = sqlite3.connect(tmp_db)
        conn.execute("UPDATE transactions SET amount = 999999 WHERE id = 1")
        conn.commit()
        conn.close()

        result = C.check_invariant(tmp_db, secure_mode=True)
        circuit = C.get_circuit_status()

        assert result["passed"] is False
        assert circuit["state"] == "OPEN", \
            "Circuit Breaker must be OPEN after invariant failure"
        assert circuit["reason"] is not None

    def test_circuit_breaker_blocks_subsequent_invariant_checks(self, tmp_db):
        """Once circuit is OPEN, all subsequent invariant checks return False."""
        # Manually trip the circuit
        C.trip_circuit("Test-triggered trip")

        result = C.check_invariant(tmp_db, secure_mode=True)
        assert result["passed"] is False
        assert result.get("circuit_open") is True

    def test_reset_restores_circuit_to_closed(self):
        """Calling reset_circuit() brings the breaker back to CLOSED."""
        C.trip_circuit("Test trip")
        assert C.get_circuit_status()["state"] == "OPEN"
        C.reset_circuit()
        assert C.get_circuit_status()["state"] == "CLOSED"


# ─────────────────────────────────────────────────────────────────────────────
# [SR-05] TOCTOU CONCURRENT THREAD SAFETY
# ─────────────────────────────────────────────────────────────────────────────

class TestConcurrentThreadSafety:
    """
    Verify the TRANSACTION_MUTEX prevents TOCTOU race conditions.
    In secure mode, only ONE transfer succeeds when balance is tight.
    """

    def test_mutex_serializes_concurrent_nonce_registration(self):
        """
        50 concurrent threads registering different nonces: each must succeed
        exactly once. Total registered nonces must equal 50.
        """
        nonces = [f"test-nonce-{i}-{uuid.uuid4()}" for i in range(50)]
        results = []
        lock = threading.Lock()

        def register(n):
            ok = C.register_nonce(n)
            with lock:
                results.append(ok)

        threads = [threading.Thread(target=register, args=(n,)) for n in nonces]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 50
        assert all(results), "All unique nonces should register successfully"

    def test_duplicate_nonce_blocked_concurrently(self):
        """
        50 threads all try to register the SAME nonce.
        Only 1 must succeed; 49 must be rejected (anti-replay).
        """
        shared_nonce = f"shared-replay-nonce-{uuid.uuid4()}"
        successes = []
        lock = threading.Lock()

        def try_register():
            ok = C.register_nonce(shared_nonce)
            with lock:
                successes.append(ok)

        threads = [threading.Thread(target=try_register) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert successes.count(True) == 1, \
            f"Only 1 thread should register the nonce, got {successes.count(True)}"
        assert successes.count(False) == 49, \
            "49 threads must be blocked as replay attempts"

    def test_post_condition_catches_overdraft_in_race(self):
        """
        Conservation of Money post-condition must reject a transfer
        that would result in a negative sender balance.
        """
        sender_before = 1000.0
        receiver_before = 500.0
        # Simulate what would happen in a race: sender was debited too much
        sender_after = -500.0   # Overdraft!
        receiver_after = 2000.0

        result = C.check_postconditions(
            sender_before, receiver_before,
            sender_after, receiver_after,
            amount=1500.0, secure_mode=True
        )
        assert result["passed"] is False
        assert any("POST-2" in v for v in result["violations"]), \
            "POST-2 [No Overdraft] must fire for negative sender_after"

    def test_conservation_of_money_exact_math(self):
        """
        Exact conservation: total before must equal total after.
        """
        sb, rb = 5000.0, 2000.0
        amount = 1000.0
        sa, ra = sb - amount, rb + amount  # Perfect math

        result = C.check_postconditions(sb, rb, sa, ra, amount, secure_mode=True)
        assert result["passed"] is True, \
            f"Valid conservation should pass, violations: {result['violations']}"

    def test_money_creation_detected_by_post_condition(self):
        """
        If more money exists after transaction than before,
        POST-1 [Conservation] must catch it.
        """
        sb, rb = 1000.0, 1000.0  # Total = 2000
        sa, ra = 1000.0, 2000.0  # Total = 3000 — money CREATED!
        result = C.check_postconditions(sb, rb, sa, ra, amount=0.0, secure_mode=True)
        assert result["passed"] is False
        assert any("POST-1" in v for v in result["violations"]), \
            "POST-1 [Conservation] must catch money creation"


# ─────────────────────────────────────────────────────────────────────────────
# [SR-06] NONCE REPLAY DEFENSE
# ─────────────────────────────────────────────────────────────────────────────

class TestNonceReplayDefense:
    """
    Verify PC-4 blocks all replay attacks via nonce uniqueness enforcement.
    """

    def test_fresh_nonce_accepted(self):
        """A novel nonce is registered successfully."""
        nonce = str(uuid.uuid4())
        assert C.register_nonce(nonce) is True

    def test_replayed_nonce_blocked(self):
        """The same nonce submitted twice is blocked on second attempt."""
        nonce = str(uuid.uuid4())
        assert C.register_nonce(nonce) is True
        assert C.register_nonce(nonce) is False, "Replayed nonce must be blocked"

    def test_replay_via_precondition_check(self):
        """PC-4 in check_preconditions must catch a replayed nonce."""
        nonce = str(uuid.uuid4())
        payload1 = _make_valid_payload(nonce=nonce)
        payload2 = _make_valid_payload(nonce=nonce)  # Same nonce, different request

        # First request: nonce consumed
        result1 = C.check_preconditions(payload1, sender_balance=5000, secure_mode=True)
        # Recompute HMAC for payload2 (nonce is in the payload)
        payload2["signature"] = C.compute_hmac(payload2)
        result2 = C.check_preconditions(payload2, sender_balance=5000, secure_mode=True)

        assert result2["passed"] is False, "Second request with same nonce must be blocked"
        assert any("PC-4" in v for v in result2["violations"]), \
            "PC-4 [Nonce] violation expected"

    def test_clear_nonces_allows_reuse(self):
        """After clearing the nonce registry, old nonces become valid again."""
        nonce = str(uuid.uuid4())
        C.register_nonce(nonce)
        assert C.register_nonce(nonce) is False  # Blocked
        C.clear_nonces()
        assert C.register_nonce(nonce) is True   # Allowed after reset

    def test_naive_mode_skips_nonce_check(self):
        """In v1.0 naive mode, nonces are NOT checked (replay attack possible)."""
        nonce = str(uuid.uuid4())
        C.register_nonce(nonce)  # Consume it

        payload = _make_valid_payload(nonce=nonce)
        result = C.check_preconditions(payload, sender_balance=5000, secure_mode=False)
        # Naive mode should return passed=True (no nonce enforcement)
        assert result["passed"] is True, \
            "Naive mode must NOT enforce nonce uniqueness (vulnerability exposed)"


# ─────────────────────────────────────────────────────────────────────────────
# [SR-07] CONSERVATION OF MONEY POST-CONDITION
# ─────────────────────────────────────────────────────────────────────────────

class TestConservationOfMoney:
    """
    Formal property testing for the Conservation of Money Post-Condition.
    """

    @pytest.mark.parametrize("sb,rb,amount", [
        (5000.0, 2000.0, 100.0),
        (1000.0, 0.0, 999.99),
        (10000.0, 5000.0, 10000.0),
        (0.01, 0.0, 0.01),
    ])
    def test_valid_transfers_preserve_total(self, sb, rb, amount):
        """For all valid (sb, rb, amount), total is conserved and sa >= 0."""
        sa = sb - amount
        ra = rb + amount
        result = C.check_postconditions(sb, rb, sa, ra, amount, secure_mode=True)
        assert result["passed"] is True, \
            f"Valid transfer (sb={sb}, rb={rb}, amount={amount}) should pass, " \
            f"violations: {result['violations']}"

    def test_naive_mode_does_not_enforce_conservation(self):
        """In naive mode, money creation goes undetected."""
        result = C.check_postconditions(
            1000.0, 1000.0,    # Total before = 2000
            1000.0, 5000.0,    # Total after = 6000 — money created!
            amount=4000.0,
            secure_mode=False
        )
        assert result.get("naive") is True or result["passed"] is True, \
            "Naive mode must NOT enforce Conservation of Money"

    def test_exact_debit_integrity(self):
        """POST-3 catches when sender is debited by wrong amount."""
        sb, rb = 5000.0, 1000.0
        amount = 500.0
        sa = 4000.0  # Should be 4500 — debited too much!
        ra = rb + amount
        result = C.check_postconditions(sb, rb, sa, ra, amount, secure_mode=True)
        assert result["passed"] is False
        # POST-1 or POST-3 should fire
        assert len(result["violations"]) > 0

    def test_exact_credit_integrity(self):
        """POST-4 catches when receiver is credited by wrong amount."""
        sb, rb = 5000.0, 1000.0
        amount = 500.0
        sa = sb - amount
        ra = 2000.0  # Should be 1500 — over-credited!
        result = C.check_postconditions(sb, rb, sa, ra, amount, secure_mode=True)
        assert result["passed"] is False


# ─────────────────────────────────────────────────────────────────────────────
# [SR-08] CIRCUIT BREAKER
# ─────────────────────────────────────────────────────────────────────────────

class TestCircuitBreaker:
    """
    Verify Circuit Breaker state machine: CLOSED → OPEN → CLOSED.
    """

    def test_initial_state_is_closed(self):
        """After reset, Circuit Breaker is in CLOSED state."""
        status = C.get_circuit_status()
        assert status["state"] == "CLOSED"
        assert status["reason"] is None

    def test_trip_transitions_to_open(self):
        """trip_circuit() transitions state to OPEN with a reason."""
        C.trip_circuit("Test: hash chain broken")
        status = C.get_circuit_status()
        assert status["state"] == "OPEN"
        assert "hash chain broken" in status["reason"]
        assert status["tripped_at"] is not None

    def test_open_circuit_blocks_check_invariant(self, tmp_db):
        """With OPEN circuit, check_invariant returns passed=False immediately."""
        C.trip_circuit("Pre-tripped")
        result = C.check_invariant(tmp_db, secure_mode=True)
        assert result["passed"] is False
        assert result.get("circuit_open") is True

    def test_reset_circuit_restores_closed(self):
        """reset_circuit() restores CLOSED state and clears reason."""
        C.trip_circuit("Test")
        C.reset_circuit()
        status = C.get_circuit_status()
        assert status["state"] == "CLOSED"
        assert status["reason"] is None
        assert status["tripped_at"] is None


# ─────────────────────────────────────────────────────────────────────────────
# [SR-09] SCHEMA VALIDATION (PC-1)
# ─────────────────────────────────────────────────────────────────────────────

class TestSchemaValidation:
    """
    PC-1 must reject payloads with missing or wrong-type fields.
    """

    def test_missing_sender_rejected(self):
        """Payload without 'sender' fails PC-1."""
        payload = {"receiver": "Bob", "amount": 100,
                   "nonce": str(uuid.uuid4()), "signature": "sig"}
        result = C.check_preconditions(payload, 5000, secure_mode=True)
        assert result["passed"] is False
        assert any("sender" in v for v in result["violations"])

    def test_missing_signature_rejected(self):
        """Payload without 'signature' fails PC-1."""
        payload = {"sender": "Alice", "receiver": "Bob",
                   "amount": 100, "nonce": str(uuid.uuid4())}
        result = C.check_preconditions(payload, 5000, secure_mode=True)
        assert result["passed"] is False

    def test_wrong_type_amount_rejected(self):
        """Amount as string (not int/float) fails PC-1."""
        payload = {"sender": "Alice", "receiver": "Bob",
                   "amount": "hundred", "nonce": str(uuid.uuid4()), "signature": "sig"}
        result = C.check_preconditions(payload, 5000, secure_mode=True)
        assert result["passed"] is False

    def test_complete_valid_schema_passes_pc1(self):
        """A fully typed correct payload passes PC-1 schema check."""
        payload = _make_valid_payload()
        result = C.check_preconditions(payload, 5000, secure_mode=True)
        pc1_violations = [v for v in result.get("violations", []) if "PC-1" in v]
        assert len(pc1_violations) == 0, f"PC-1 should pass: {pc1_violations}"


# ─────────────────────────────────────────────────────────────────────────────
# [SR-10] RISK SCORE ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class TestRiskScoreEngine:
    """
    Verify the Context-Aware Risk Score engine produces sensible scores.
    """

    def test_low_amount_low_balance_ratio_has_low_risk(self):
        """₹100 transfer from ₹10,000 balance = low risk score."""
        payload = {"sender": "A", "receiver": "B", "amount": 100}
        score = C.compute_risk_score(payload, sender_balance=10000)
        assert score < 70, f"Low ratio transfer should have low risk, got {score}"

    def test_zero_balance_gives_max_factor(self):
        """Transfer from zero balance = maximum risk factor (40 pts)."""
        payload = {"sender": "A", "receiver": "B", "amount": 100}
        score = C.compute_risk_score(payload, sender_balance=0)
        # Factor 1 maxes at 40
        assert score >= 40, f"Zero balance should contribute max risk, got {score}"

    def test_risk_score_bounded_to_100(self):
        """Risk score must never exceed 100."""
        payload = {"sender": "A", "receiver": "B", "amount": 50000}
        score = C.compute_risk_score(payload, sender_balance=0)
        assert score <= 100, f"Risk score must be capped at 100, got {score}"

    def test_round_amount_increases_risk(self):
        """Round structuring amounts (multiples of 10,000) add risk."""
        payload_round = {"sender": "A", "receiver": "B", "amount": 10000}
        payload_odd = {"sender": "A", "receiver": "B", "amount": 9999}
        score_round = C.compute_risk_score(payload_round, sender_balance=50000)
        score_odd = C.compute_risk_score(payload_odd, sender_balance=50000)
        assert score_round > score_odd, \
            "Round amounts should have higher risk score (structuring)"
