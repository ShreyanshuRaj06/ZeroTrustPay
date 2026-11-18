"""
app.py — ZeroTrustPay: Production-Grade Secure Flask + SQLite FinTech Backend
==============================================================================
Author      : Shreyanshu Raj
Module      : Secure Software Engineering (5th Semester)
Architecture: Contract-Driven Zero-Trust FinTech

Endpoints:
  GET  /                      → Serve SDLC Workbench Dashboard
  POST /api/transfer          → @secure_contract guarded money transfer
  GET  /api/ledger            → Full hash-chained ledger with verification
  GET  /api/balances          → Live wallet balances
  GET  /api/telemetry         → Real-time contract telemetry log
  GET  /api/circuit           → Circuit Breaker status
  POST /api/mode              → Toggle v1.0 Naive / v2.0 Secure mode
  POST /api/reset             → Full demo environment reset
  POST /api/attack/race       → Red-Team: TOCTOU parallel race condition
  POST /api/attack/tamper     → Red-Team: Insider DB tamper (hash-chain break)
  POST /api/attack/mitm       → Red-Team: MITM payload tampering + replay
  POST /api/attack/negative   → Red-Team: Negative-amount balance theft
  POST /api/self_heal         → Self-heal: restore ledger from snapshot
  POST /api/run_tests         → Live pytest execution
  GET  /api/circuit/reset     → Reset Circuit Breaker (admin)
"""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from flask import Flask, jsonify, render_template, request

import contracts as C

# ─────────────────────────────────────────────────────────────────────────────
# APPLICATION BOOTSTRAP
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = "ZeroTrustPay-Flask-Secret-SSE-2024"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "zerotrust.db")
SNAPSHOT_PATH = os.path.join(BASE_DIR, "ledger_snapshot.json")

# Global mode flag: True = v2.0 Secure, False = v1.0 Naive
SECURE_MODE = True
_MODE_LOCK = threading.Lock()

# Initial balances (for demo reset)
INITIAL_BALANCES = {
    "Shreyanshu": 20000.0,
    "Merchant_Store": 80000.0,
}


def get_db_path() -> str:
    return DB_PATH


def get_secure_mode() -> bool:
    with _MODE_LOCK:
        return SECURE_MODE


def set_secure_mode(val: bool):
    global SECURE_MODE
    with _MODE_LOCK:
        SECURE_MODE = val


# ─────────────────────────────────────────────────────────────────────────────
# DATABASE LAYER
# ─────────────────────────────────────────────────────────────────────────────

def get_conn() -> sqlite3.Connection:
    """Return a SQLite connection with row_factory for dict-like access."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # Write-Ahead Logging for concurrency
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """
    Initialize database schema and seed demo data.
    Called once on startup. Idempotent — safe to call repeatedly.
    """
    conn = get_conn()
    cur = conn.cursor()

    # Wallets table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS wallets (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            balance  REAL NOT NULL DEFAULT 0.0
        )
    """)

    # Hash-chained ledger
    cur.execute("""
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
        )
    """)

    # Contract violation audit log
    cur.execute("""
        CREATE TABLE IF NOT EXISTS violations (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            phase     TEXT NOT NULL,
            message   TEXT NOT NULL,
            detail    TEXT
        )
    """)

    conn.commit()

    # Seed wallets with INITIAL_BALANCES
    for username, balance in INITIAL_BALANCES.items():
        cur.execute("""
            INSERT INTO wallets (username, balance) VALUES (?, ?)
            ON CONFLICT(username) DO UPDATE SET balance = excluded.balance
        """, (username, balance))
    conn.commit()
    conn.close()

    # Save initial snapshot
    _save_snapshot()
    print(f"[ZeroTrustPay] ✅ Database initialized at {DB_PATH}")


def _get_balance(username: str, conn: Optional[sqlite3.Connection] = None) -> float:
    """Fetch a wallet balance. Optionally reuses an existing connection."""
    close = False
    if conn is None:
        conn = get_conn()
        close = True
    try:
        row = conn.execute(
            "SELECT balance FROM wallets WHERE username = ?", (username,)
        ).fetchone()
        return float(row["balance"]) if row else 0.0
    finally:
        if close:
            conn.close()


def _set_balance(username: str, balance: float, conn: sqlite3.Connection):
    """Update wallet balance within an existing connection (transactional)."""
    conn.execute(
        "UPDATE wallets SET balance = ? WHERE username = ?",
        (round(balance, 6), username)
    )


def _get_last_hash(conn: sqlite3.Connection) -> str:
    """Return the hash of the most recent ledger entry, or 'GENESIS'."""
    row = conn.execute(
        "SELECT curr_hash FROM transactions ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row["curr_hash"] if row else "GENESIS"


def _append_ledger_entry(conn: sqlite3.Connection, sender: str, receiver: str,
                         amount: float, nonce: str = "", status: str = "SUCCESS"):
    """Append a new hash-chained block to the transactions table."""
    ts = datetime.now(timezone.utc).isoformat()
    prev_hash = _get_last_hash(conn)
    curr_hash = C.compute_ledger_hash(prev_hash, sender, receiver, amount, ts)

    conn.execute("""
        INSERT INTO transactions
            (sender, receiver, amount, timestamp, prev_hash, curr_hash, nonce, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (sender, receiver, round(amount, 6), ts, prev_hash, curr_hash, nonce, status))

    return {"ts": ts, "prev_hash": prev_hash, "curr_hash": curr_hash}


def _save_snapshot():
    """
    Save current DB state as a JSON snapshot for self-healing restoration.
    Captures wallet balances and full ledger hash chain.
    """
    try:
        conn = get_conn()
        wallets = [dict(r) for r in conn.execute("SELECT * FROM wallets").fetchall()]
        txns = [dict(r) for r in conn.execute(
            "SELECT * FROM transactions ORDER BY id"
        ).fetchall()]
        conn.close()

        with open(SNAPSHOT_PATH, "w") as f:
            json.dump({
                "snapshot_ts": datetime.now(timezone.utc).isoformat(),
                "wallets": wallets,
                "transactions": txns
            }, f, indent=2)
    except Exception as e:
        print(f"[ZeroTrustPay] ⚠ Snapshot save failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# CORE TRANSACTION FUNCTION (wrapped by @secure_contract)
# ─────────────────────────────────────────────────────────────────────────────

@C.secure_contract(get_db_path, get_secure_mode)
def _execute_transfer(payload: dict, sender_balance: float,
                      receiver_balance: float) -> dict:
    """
    Atomic financial transaction — executes ONLY after all contracts pass.

    This function runs INSIDE the @secure_contract decorator which enforces:
    Pre-conditions → Pre-Invariant → [THIS FUNCTION] → Post-Invariant → Post-conditions

    Returns the new balances so the Post-condition can verify Conservation of Money.
    """
    sender = payload["sender"]
    receiver = payload["receiver"]
    amount = float(payload["amount"])
    nonce = payload.get("nonce", str(uuid.uuid4()))

    new_sender_bal = round(sender_balance - amount, 6)
    new_receiver_bal = round(receiver_balance + amount, 6)

    # Formal Post-Condition Enforcement: No Overdraft Law
    if new_sender_bal < 0:
        raise C.PostConditionError(
            f"POST-2 [No Overdraft]: Sender balance after={new_sender_bal:.2f} < 0. "
            "Overdraft would violate financial invariant. ROLLED BACK."
        )

    conn = get_conn()
    try:
        conn.execute("BEGIN EXCLUSIVE")  # Exclusive lock — TOCTOU protection
        _set_balance(sender, new_sender_bal, conn)
        _set_balance(receiver, new_receiver_bal, conn)
        ledger = _append_ledger_entry(conn, sender, receiver, amount, nonce)
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        raise RuntimeError(f"DB write failed: {e}")
    conn.close()

    _save_snapshot()  # Update snapshot after successful write

    return {
        "sender_after": new_sender_bal,
        "receiver_after": new_receiver_bal,
        "ledger": ledger,
        "tx_id": nonce,
    }


# ─────────────────────────────────────────────────────────────────────────────
# FLASK API ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/balances")
def api_balances():
    conn = get_conn()
    rows = conn.execute("SELECT username, balance FROM wallets").fetchall()
    conn.close()
    return jsonify({
        "balances": {r["username"]: round(float(r["balance"]), 2) for r in rows},
        "mode": "secure" if get_secure_mode() else "naive"
    })


@app.route("/api/ledger")
def api_ledger():
    conn = get_conn()
    rows = conn.execute("""
        SELECT id, sender, receiver, amount, timestamp,
               prev_hash, curr_hash, nonce, status
        FROM transactions ORDER BY id ASC
    """).fetchall()
    conn.close()

    ledger = []
    for r in rows:
        ledger.append({
            "id": r["id"],
            "sender": r["sender"],
            "receiver": r["receiver"],
            "amount": r["amount"],
            "timestamp": r["timestamp"],
            "prev_hash": r["prev_hash"][:12] + "..." if r["prev_hash"] != "GENESIS" else "GENESIS",
            "prev_hash_full": r["prev_hash"],
            "curr_hash": r["curr_hash"][:12] + "...",
            "curr_hash_full": r["curr_hash"],
            "nonce": (r["nonce"] or "")[:8] + "...",
            "status": r["status"],
        })

    # Recompute verification status per row
    chain_result = C.verify_ledger_chain(DB_PATH)
    corrupted_ids = {c["id"] for c in chain_result.get("corrupted_rows", [])}
    for entry in ledger:
        entry["verified"] = entry["id"] not in corrupted_ids

    return jsonify({
        "ledger": ledger,
        "chain_valid": chain_result["valid"],
        "corrupted_rows": chain_result.get("corrupted_rows", []),
        "total": len(ledger)
    })


@app.route("/api/telemetry")
def api_telemetry():
    n = int(request.args.get("n", 60))
    return jsonify({
        "telemetry": C.get_telemetry(n),
        "circuit": C.get_circuit_status(),
        "mode": "secure" if get_secure_mode() else "naive",
        "nonce_count": C.get_nonce_count(),
    })


@app.route("/api/circuit")
def api_circuit():
    return jsonify(C.get_circuit_status())


@app.route("/api/circuit/reset", methods=["POST", "GET"])
def api_circuit_reset():
    C.reset_circuit()
    return jsonify({"status": "ok", "message": "Circuit Breaker reset to CLOSED"})


@app.route("/api/mode", methods=["GET", "POST"])
def api_mode():
    if request.method == "POST":
        data = request.get_json(force=True) or {}
        mode = data.get("mode", "secure")
        set_secure_mode(mode == "secure")
        C._emit("INFO", "PRE",
                f"🔄 Mode switched to: {'v2.0 Secure SE' if get_secure_mode() else 'v1.0 Naive/Unengineered'}",
                {"mode": mode})
        return jsonify({
            "mode": mode,
            "secure": get_secure_mode(),
            "message": f"Switched to {'Contract-Driven Secure SE (v2.0)' if get_secure_mode() else 'Naive Unengineered (v1.0)'}"
        })
    return jsonify({
        "mode": "secure" if get_secure_mode() else "naive",
        "secure": get_secure_mode()
    })


@app.route("/api/transfer", methods=["POST"])
def api_transfer():
    data = request.get_json(force=True)

    sender = data.get("sender", "")
    receiver = data.get("receiver", "")
    amount = data.get("amount", 0)
    nonce = data.get("nonce") or str(uuid.uuid4())

    # Build signed payload (in real app, client would sign; here server signs for demo)
    payload = {
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "nonce": nonce,
    }

    # If client provided a signature, use it; otherwise compute (demo convenience)
    if "signature" in data:
        payload["signature"] = data["signature"]
    else:
        payload["signature"] = C.compute_hmac(payload)

    sender_balance = _get_balance(sender)
    receiver_balance = _get_balance(receiver)

    try:
        result = _execute_transfer(payload, sender_balance, receiver_balance)
        return jsonify({
            "status": "success",
            "message": f"₹{amount} transferred from {sender} to {receiver}",
            "tx_id": result.get("tx_id"),
            "sender_balance": result["sender_after"],
            "receiver_balance": result["receiver_after"],
        })

    except C.PreConditionError as e:
        return jsonify({
            "status": "blocked",
            "phase": "PRE-CONDITION",
            "message": str(e),
            "contract_enforcement": "✅ v2.0 Secure contract blocked this attack"
        }), 400

    except C.InvariantError as e:
        return jsonify({
            "status": "blocked",
            "phase": "SYSTEM INVARIANT",
            "message": str(e),
            "circuit_state": C.get_circuit_status(),
            "contract_enforcement": "✅ Hash-chain invariant + Circuit Breaker activated"
        }), 400

    except C.PostConditionError as e:
        return jsonify({
            "status": "rolled_back",
            "phase": "POST-CONDITION",
            "message": str(e),
            "contract_enforcement": "✅ Conservation of Money law enforced — rollback complete"
        }), 400

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/api/reset", methods=["POST"])
def api_reset():
    """
    Full demo environment reset:
    - Restore initial balances
    - Clear transaction ledger
    - Reset Circuit Breaker
    - Clear nonce registry
    - Clear telemetry
    - Rebuild snapshot
    """
    try:
        conn = get_conn()
        conn.execute("DELETE FROM transactions")
        conn.execute("DELETE FROM violations")
        for username, balance in INITIAL_BALANCES.items():
            conn.execute(
                "UPDATE wallets SET balance = ? WHERE username = ?",
                (balance, username)
            )
        conn.commit()
        conn.close()

        C.reset_circuit()
        C.clear_nonces()
        C.clear_telemetry()
        _save_snapshot()

        C._emit("INFO", "PRE", "🔄 Demo environment RESET — all state restored to initial values")

        return jsonify({
            "status": "ok",
            "message": "Demo environment fully reset",
            "balances": INITIAL_BALANCES
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# RED-TEAM ATTACK SIMULATORS
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/attack/race", methods=["POST"])
def attack_race():
    """
    Attack 1: TOCTOU Parallel Race Condition
    Fires 5 concurrent ₹6,000 transfers from Shreyanshu (balance ₹20,000).
    
    v1.0 (Naive):  No mutex → race window → balance can go to -₹10,000
    v2.0 (Secure): Atomic mutex + post-condition blocks all overdraft attempts
    """
    secure = get_secure_mode()
    results = []
    threads = []
    lock = threading.Lock()

    def fire_transfer(thread_id: int):
        nonce = f"race-{thread_id}-{uuid.uuid4()}"
        payload = {
            "sender": "Shreyanshu",
            "receiver": "Merchant_Store",
            "amount": 6000,
            "nonce": nonce,
        }
        payload["signature"] = C.compute_hmac(payload)

        sender_bal = _get_balance("Shreyanshu")
        receiver_bal = _get_balance("Merchant_Store")

        try:
            if secure:
                result = _execute_transfer(payload, sender_bal, receiver_bal)
                outcome = {
                    "thread": thread_id,
                    "status": "SUCCESS",
                    "sender_after": result["sender_after"],
                    "message": f"Thread-{thread_id}: ₹6,000 transferred"
                }
            else:
                # Naive: bypass contract, simulate TOCTOU check-then-act race
                conn = get_conn()
                s_bal = _get_balance("Shreyanshu", conn)
                time.sleep(0.02)  # Race window opens: all 5 threads check balance before any deduct
                conn.execute("UPDATE wallets SET balance = balance - 6000 WHERE username = 'Shreyanshu'")
                conn.execute("UPDATE wallets SET balance = balance + 6000 WHERE username = 'Merchant_Store'")
                cur = conn.cursor()
                cur.execute("SELECT balance FROM wallets WHERE username = 'Shreyanshu'")
                new_s = float(cur.fetchone()[0])
                _append_ledger_entry(conn, "Shreyanshu", "Merchant_Store", 6000, nonce)
                conn.commit()
                conn.close()
                outcome = {
                    "thread": thread_id,
                    "status": "SUCCESS_NAIVE",
                    "sender_after": new_s,
                    "message": f"Thread-{thread_id}: ₹6,000 transferred (RACE EXPLOITED! balance=₹{new_s})"
                }

        except (C.PreConditionError, C.PostConditionError, C.InvariantError) as e:
            outcome = {
                "thread": thread_id,
                "status": "BLOCKED",
                "message": f"Thread-{thread_id}: BLOCKED by contract — {str(e)[:120]}"
            }
        except Exception as e:
            outcome = {
                "thread": thread_id,
                "status": "ERROR",
                "message": f"Thread-{thread_id}: Error — {str(e)[:120]}"
            }

        with lock:
            results.append(outcome)

    # Launch 5 threads simultaneously
    for i in range(1, 6):
        t = threading.Thread(target=fire_transfer, args=(i,))
        threads.append(t)

    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    elapsed = round(time.time() - start, 3)

    final_balance = _get_balance("Shreyanshu")

    C._emit("WARN", "PRE",
            f"🔴 Race Attack completed in {elapsed}s | Final Shreyanshu balance: ₹{final_balance}",
            {"results": results, "final_balance": final_balance})

    return jsonify({
        "attack": "TOCTOU Race Condition",
        "threads": 5,
        "amount_per_thread": 6000,
        "initial_balance": 20000,
        "final_balance": final_balance,
        "elapsed_seconds": elapsed,
        "results": results,
        "verdict": (
            "✅ SECURE: Atomic mutex + post-condition blocked overdraft. "
            f"Balance preserved at ₹{final_balance}"
            if secure else
            f"⛔ VULNERABLE: Race condition exploited! Balance = ₹{final_balance} "
            "(should be ₹20,000 or ₹2,000, not negative)"
        ),
        "mode": "secure" if secure else "naive"
    })


@app.route("/api/attack/tamper", methods=["POST"])
def attack_tamper():
    """
    Attack 2: Insider Database Tampering (Direct SQL balance edit)
    Directly updates the transactions table without recomputing hashes.
    
    v1.0 (Naive):  Tampering undetected — insider keeps ₹99,000
    v2.0 (Secure): Hash-chain invariant catches the broken block → Circuit Breaker
    """
    secure = get_secure_mode()

    # First: add a legitimate transaction to have something to tamper
    conn = get_conn()
    s_bal = _get_balance("Shreyanshu", conn)

    # Insert a legit entry if ledger is empty
    rows = conn.execute("SELECT COUNT(*) as cnt FROM transactions").fetchone()
    if rows["cnt"] == 0:
        # Seed one legitimate entry
        _append_ledger_entry(conn, "Shreyanshu", "Merchant_Store", 100.0, "init-seed")
        conn.commit()

    # Insider tampers: directly edits the amount on row 1 without updating curr_hash
    tampered_row = conn.execute(
        "SELECT id FROM transactions ORDER BY id ASC LIMIT 1"
    ).fetchone()

    if tampered_row:
        tampered_id = tampered_row["id"]
        # Raw SQL injection-style update: adds ₹99,000 to amount without touching hashes
        conn.execute(
            "UPDATE transactions SET amount = amount + 99000 WHERE id = ?",
            (tampered_id,)
        )
        conn.commit()
        tamper_msg = (
            f"💉 Insider executed: UPDATE transactions SET amount = amount + 99000 "
            f"WHERE id = {tampered_id}"
        )
    else:
        tampered_id = None
        tamper_msg = "No rows to tamper"

    conn.close()

    C._emit("WARN", "INV",
            f"🔴 Insider DB tamper injected on row {tampered_id}",
            {"raw_sql": tamper_msg})

    if secure:
        # Now run invariant check — it MUST detect the broken hash
        inv_result = C.check_invariant(DB_PATH, secure_mode=True)
        circuit = C.get_circuit_status()
        return jsonify({
            "attack": "Insider DB Tampering",
            "tamper_sql": tamper_msg,
            "tampered_row_id": tampered_id,
            "invariant_check": inv_result,
            "circuit_breaker": circuit,
            "verdict": (
                "✅ SECURE: SHA-256 hash-chain invariant detected the tampered block. "
                "Circuit Breaker TRIPPED — all mutations frozen until self-heal."
                if not inv_result["passed"]
                else "⚠ Invariant passed (unexpected — please reset and retry)"
            ),
            "mode": "secure"
        })
    else:
        # Naive: no verification, tampering goes undetected
        C._emit("WARN", "INV",
                "v1.0 NAIVE: Insider DB tamper NOT detected — no hash verification",
                {"tampered_id": tampered_id})
        balance = _get_balance("Shreyanshu")
        return jsonify({
            "attack": "Insider DB Tampering",
            "tamper_sql": tamper_msg,
            "tampered_row_id": tampered_id,
            "verdict": (
                f"⛔ VULNERABLE (v1.0): Tamper UNDETECTED. "
                f"No hash chain check in naive mode. "
                f"Insider successfully inflated ledger entry by ₹99,000."
            ),
            "mode": "naive"
        })


@app.route("/api/attack/mitm", methods=["POST"])
def attack_mitm():
    """
    Attack 3: MITM Parameter Tampering + Replay Attack
    Client signs a ₹100 transfer; attacker changes amount to ₹4,500 in-transit.
    
    v1.0 (Naive):  HMAC not verified → tampered amount accepted
    v2.0 (Secure): HMAC-SHA256 mismatch detected → PC-5 contract blocks transfer
    """
    secure = get_secure_mode()

    # Original legitimate payload (signed for ₹100)
    original_payload = {
        "sender": "Shreyanshu",
        "receiver": "Merchant_Store",
        "amount": 100,
        "nonce": f"mitm-{uuid.uuid4()}",
    }
    original_signature = C.compute_hmac(original_payload)
    original_payload["signature"] = original_signature

    # MITM attacker intercepts and modifies amount to ₹4,500
    tampered_payload = dict(original_payload)
    tampered_payload["amount"] = 4500  # Modified in-transit!
    # Signature NOT updated — attacker doesn't know the HMAC key

    C._emit("WARN", "PRE",
            "🔴 MITM Attack: Signed ₹100 payload tampered to ₹4,500 in-transit",
            {
                "original_amount": 100,
                "tampered_amount": 4500,
                "signature_valid_for_original": True,
                "attacker_has_hmac_key": False
            })

    sender_bal = _get_balance("Shreyanshu")
    receiver_bal = _get_balance("Merchant_Store")

    if secure:
        pre = C.check_preconditions(tampered_payload, sender_bal, secure_mode=True)
        return jsonify({
            "attack": "MITM Parameter Tampering + Replay",
            "original_amount": 100,
            "tampered_amount": 4500,
            "original_signature": original_signature[:20] + "...",
            "signature_matches_tampered": False,
            "precondition_result": pre,
            "verdict": (
                "✅ SECURE: PC-5 [HMAC] contract detected payload tampering. "
                "HMAC-SHA256 mismatch — transfer BLOCKED. Attacker gets ₹0."
                if not pre["passed"]
                else "⚠ Unexpected pass — check HMAC logic"
            ),
            "mode": "secure"
        })
    else:
        # Naive: no HMAC check, tampered amount goes through
        conn = get_conn()
        s_bal = _get_balance("Shreyanshu", conn)
        r_bal = _get_balance("Merchant_Store", conn)
        new_s = s_bal - 4500  # Full tampered amount deducted!
        new_r = r_bal + 4500
        _set_balance("Shreyanshu", new_s, conn)
        _set_balance("Merchant_Store", new_r, conn)
        _append_ledger_entry(conn, "Shreyanshu", "Merchant_Store", 4500,
                             tampered_payload["nonce"])
        conn.commit()
        conn.close()
        C._emit("WARN", "PRE",
                f"v1.0 NAIVE: MITM tamper succeeded — ₹4,500 stolen (original: ₹100)",
                {"sender_new_balance": new_s})
        return jsonify({
            "attack": "MITM Parameter Tampering + Replay",
            "original_amount": 100,
            "tampered_amount": 4500,
            "verdict": (
                f"⛔ VULNERABLE (v1.0): MITM tamper SUCCEEDED. "
                f"₹4,500 transferred instead of ₹100. "
                f"Shreyanshu balance: ₹{new_s}"
            ),
            "mode": "naive"
        })


@app.route("/api/attack/negative", methods=["POST"])
def attack_negative():
    """
    Attack 4: Integer Overflow / Negative Transfer Exploit
    Transfers amount = -5000 to reverse money flow (steal from receiver).
    
    v1.0 (Naive):  Negative amount accepted → money stolen
    v2.0 (Secure): PC-2 [Amount Bounds] + Post-Condition catch and block
    """
    secure = get_secure_mode()

    # Attacker constructs a negative-amount transfer
    nonce = f"neg-{uuid.uuid4()}"
    evil_payload = {
        "sender": "Shreyanshu",
        "receiver": "Merchant_Store",
        "amount": -5000,  # Negative — this reverses the math!
        "nonce": nonce,
    }
    evil_payload["signature"] = C.compute_hmac(evil_payload)

    C._emit("WARN", "PRE",
            "🔴 Negative Amount Attack: amount=-₹5,000 submitted to steal from receiver",
            {"amount": -5000, "attack_vector": "balance reversal"})

    sender_bal = _get_balance("Shreyanshu")
    receiver_bal = _get_balance("Merchant_Store")

    if secure:
        pre = C.check_preconditions(evil_payload, sender_bal, secure_mode=True)
        return jsonify({
            "attack": "Negative Transfer Exploit",
            "submitted_amount": -5000,
            "sender_balance_before": sender_bal,
            "receiver_balance_before": receiver_bal,
            "precondition_result": pre,
            "verdict": (
                "✅ SECURE: PC-2 [Amount Bounds] contract caught negative amount. "
                "Transfer blocked. No money stolen."
                if not pre["passed"]
                else "⚠ Unexpected pass"
            ),
            "mode": "secure"
        })
    else:
        # Naive: no bounds check → negative amount reverses the math
        conn = get_conn()
        s_bal = _get_balance("Shreyanshu", conn)
        r_bal = _get_balance("Merchant_Store", conn)
        # sender - (-5000) = sender + 5000 (money APPEARS in sender's account!)
        new_s = s_bal - (-5000)   # = s_bal + 5000
        new_r = r_bal + (-5000)   # = r_bal - 5000
        _set_balance("Shreyanshu", new_s, conn)
        _set_balance("Merchant_Store", new_r, conn)
        _append_ledger_entry(conn, "Shreyanshu", "Merchant_Store", -5000, nonce)
        conn.commit()
        conn.close()
        C._emit("CRITICAL", "PRE",
                f"v1.0 NAIVE: Negative exploit SUCCEEDED — Shreyanshu stole ₹5,000!",
                {"new_sender_balance": new_s, "new_receiver_balance": new_r})
        return jsonify({
            "attack": "Negative Transfer Exploit",
            "submitted_amount": -5000,
            "sender_balance_before": sender_bal,
            "receiver_balance_before": receiver_bal,
            "sender_balance_after": new_s,
            "receiver_balance_after": new_r,
            "verdict": (
                f"⛔ VULNERABLE (v1.0): Negative exploit SUCCEEDED! "
                f"Shreyanshu's balance: ₹{s_bal} → ₹{new_s} (+₹5,000 stolen). "
                f"Merchant_Store: ₹{r_bal} → ₹{new_r} (victim lost ₹5,000)."
            ),
            "mode": "naive"
        })


@app.route("/api/self_heal", methods=["POST"])
def api_self_heal():
    """
    Self-Heal: Restore ledger from last known-good snapshot.
    Resets circuit breaker after successful restoration.
    """
    if not os.path.exists(SNAPSHOT_PATH):
        return jsonify({
            "status": "error",
            "message": "No snapshot found — please reset the demo first"
        }), 400

    try:
        with open(SNAPSHOT_PATH, "r") as f:
            snap = json.load(f)

        conn = get_conn()
        conn.execute("DELETE FROM transactions")
        for w in snap["wallets"]:
            conn.execute(
                "UPDATE wallets SET balance = ? WHERE username = ?",
                (w["balance"], w["username"])
            )
        for tx in snap["transactions"]:
            conn.execute("""
                INSERT INTO transactions
                    (id, sender, receiver, amount, timestamp,
                     prev_hash, curr_hash, nonce, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (tx["id"], tx["sender"], tx["receiver"], tx["amount"],
                  tx["timestamp"], tx["prev_hash"], tx["curr_hash"],
                  tx.get("nonce", ""), tx.get("status", "SUCCESS")))
        conn.commit()
        conn.close()

        C.reset_circuit()
        C._emit("INFO", "CIRCUIT",
                "✅ Self-Heal complete — ledger restored from snapshot, Circuit Breaker reset")

        return jsonify({
            "status": "ok",
            "message": "Ledger restored from snapshot. Circuit Breaker reset.",
            "snapshot_ts": snap.get("snapshot_ts"),
            "restored_transactions": len(snap["transactions"]),
            "circuit": C.get_circuit_status()
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# LIVE PYTEST RUNNER
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/run_tests", methods=["POST"])
def api_run_tests():
    """
    Execute test_sse_suite.py via pytest subprocess and stream the results.
    Returns structured pass/fail per test with timing.
    """
    test_file = os.path.join(BASE_DIR, "test_sse_suite.py")
    if not os.path.exists(test_file):
        return jsonify({
            "status": "error",
            "message": "test_sse_suite.py not found"
        }), 404

    start_ts = time.time()
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", test_file,
             "-v", "--tb=short", "--no-header",
             "--color=no", "-x"],  # -x: stop on first failure for speed
            capture_output=True,
            text=True,
            timeout=60,
            cwd=BASE_DIR
        )
        elapsed = round(time.time() - start_ts, 2)
        stdout = result.stdout
        stderr = result.stderr

        # Parse pytest output into structured test results
        tests = []
        for line in stdout.splitlines():
            if " PASSED" in line or " FAILED" in line or " ERROR" in line:
                parts = line.strip().split()
                status_word = "PASSED" if "PASSED" in line else ("FAILED" if "FAILED" in line else "ERROR")
                name = line.split("::")[1].split(" ")[0] if "::" in line else line
                tests.append({
                    "name": name,
                    "status": status_word,
                    "passed": status_word == "PASSED"
                })

        # Extract summary line
        summary = ""
        for line in reversed(stdout.splitlines()):
            if "passed" in line or "failed" in line or "error" in line:
                summary = line.strip()
                break

        passed_count = sum(1 for t in tests if t["passed"])
        total_count = len(tests)

        C._emit("INFO", "PRE",
                f"🧪 pytest ran {total_count} tests: {passed_count} passed, "
                f"{total_count - passed_count} failed — {elapsed}s",
                {"summary": summary})

        return jsonify({
            "status": "ok" if result.returncode == 0 else "failed",
            "returncode": result.returncode,
            "tests": tests,
            "passed": passed_count,
            "total": total_count,
            "elapsed": elapsed,
            "summary": summary,
            "stdout": stdout[-4000:],  # Last 4KB
            "stderr": stderr[-1000:],
        })

    except subprocess.TimeoutExpired:
        return jsonify({
            "status": "error",
            "message": "Test suite timed out after 60 seconds"
        }), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print("  ZeroTrustPay — Secure SDLC Workbench")
    print("  Author: Shreyanshu Raj | Secure Software Engineering (5th Sem)")
    print("  Architecture: Contract-Driven Zero-Trust FinTech")
    print("=" * 70)
    init_db()
    C._emit("INFO", "PRE",
            "🚀 ZeroTrustPay server started — Contract-Driven Security Active",
            {"mode": "v2.0 Secure SE", "port": 5000})
    app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=False, threaded=True)
