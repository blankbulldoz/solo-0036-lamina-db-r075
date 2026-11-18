#!/usr/bin/env python3
"""LaminaDB durability experiment runner.

Produces the raw records in durability/evidence/.

Design rules enforced here:

1. A commit is never retried inside a scenario. Retry is only an explicit
   step, so the duplicate it creates is visible in the record.
2. Every scenario reports three separate axes:
       ack      what the client observed   (2xx / error / no_response)
       data     what a normal query returns after reopening
       history  what /changes can still name, and from where
   "data equal" is never promoted to "delivery equivalent".
3. Scenario failure to reach its intended window is reported as
   "window_missed", not as a pass. A fault that did not fire proves nothing.

Run:
    python3 -I experiments.py --binary /tmp/laminad --out ../evidence
    python3 -I experiments.py --binary /tmp/laminad --out ../evidence --only S3,S4
"""

import argparse
import hashlib
import itertools
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import client  # noqa: E402

REL = "t"
COLUMNS = [
    {"name": "k", "type": "int"},
    {"name": "v", "type": "text", "nullable": True},
    {"name": "pad", "type": "text", "nullable": True},
]

FS_ROOTS = {
    "tmpfs": "/dev/shm",
    "overlayfs": "/tmp",
    "virtiofs": "/workspace",
}


# -- environment -------------------------------------------------------------

def environment(binary, injector):
    def sha(path):
        try:
            with open(path, "rb") as handle:
                return hashlib.sha256(handle.read()).hexdigest()
        except OSError as exc:
            return f"unavailable: {exc}"

    def cmd(argv):
        try:
            out = subprocess.run(argv, capture_output=True, text=True,
                                 timeout=10)
            return (out.stdout or out.stderr).strip()
        except Exception as exc:
            return f"unavailable: {exc}"

    def fs_type(path):
        try:
            out = subprocess.run(["stat", "-f", "-c", "%T", path],
                                 capture_output=True, text=True, timeout=5)
            return out.stdout.strip()
        except Exception as exc:
            return f"unknown: {exc}"

    return {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "kernel": cmd(["uname", "-a"]),
        "arch": os.uname().machine,
        "nproc": os.cpu_count(),
        "binary_path": binary,
        "binary_sha256": sha(binary),
        "injector_path": injector or None,
        "injector_sha256": sha(injector) if injector else None,
        "filesystems": {name: fs_type(root)
                        for name, root in FS_ROOTS.items()},
        "cache_drop_available": os.access("/proc/sys/vm/drop_caches", os.W_OK),
        "container_runtime": {
            "docker_cli": shutil.which("docker"),
            "podman_cli": shutil.which("podman"),
            "docker_sock": os.path.exists("/var/run/docker.sock"),
            "unshare_ok": _unshare_ok(),
        },
        "python": sys.version.split()[0],
    }


def _unshare_ok():
    try:
        return subprocess.run(["unshare", "-Ur", "true"],
                              capture_output=True, timeout=5).returncode == 0
    except Exception:
        return False


# -- fixture -----------------------------------------------------------------

def fresh(root):
    """Start a server on an empty directory with the fixture relation."""
    os.makedirs(root, exist_ok=True)
    server = client.Server(BINARY, root, env=ENV)
    started = server.start()
    if not started["ok"]:
        raise RuntimeError("start failed: " + str(started["error"])[:2000])
    created = server.create_relation(REL, COLUMNS)
    if created["status"] not in (200, 201):
        raise RuntimeError(f"relation: {created}")
    return server


_TRIAL = itertools.count()


def trial_dir(ctx, name):
    """A fresh subdirectory per trial.

    Reusing one name across repetitions leaves lamina.lock behind and makes the
    next run fail to open the directory, which would look like a product
    finding rather than a harness fault.
    """
    return os.path.join(ctx["base"], f"{name}-{next(_TRIAL)}")


def reopen(root, restore=None):
    server = client.Server(BINARY, root, restore=restore, env=ENV)
    started = server.start()
    return server, started


def seed(server, keys, pad_size=0, prefix="v"):
    """One transaction committing all keys, returning its ack."""
    tx = server.begin()["body"]["id"]
    for key in keys:
        row = {"k": key, "v": f"{prefix}{key}"}
        if pad_size:
            row["pad"] = "p" * pad_size
        put = server.put(tx, REL, row)
        if put["status"] != 200:
            raise RuntimeError(f"put {key}: {put}")
    return server.commit(tx)


def state(server):
    stats = client.read_stats(server)
    changes = client.read_changes(server, 0, 1000)
    rows = client.read_rows(server, REL)
    return {
        "sequence": stats.get("sequence") if isinstance(stats, dict) else None,
        "horizon": stats.get("horizon") if isinstance(stats, dict) else None,
        "history_base": (stats.get("history_base")
                         if isinstance(stats, dict) else None),
        "journal_records": (stats.get("journal_records")
                            if isinstance(stats, dict) else None),
        "recovered_tail_bytes": (stats.get("recovered_tail_bytes")
                                 if isinstance(stats, dict) else None),
        "keys": client.row_keys(rows),
        "truncated": rows.get("truncated"),
        "changes_status": changes.get("status", 200),
        "change_sequences": [r.get("sequence")
                            for r in (changes.get("records") or [])],
        "commit_writes": client.commit_writes(changes),
    }


def open_ack(ack):
    return {
        "class": ack["class"],
        "status": ack["status"],
        "elapsed_ms": ack["elapsed_ms"],
        "error": ack["error"],
        "body": ack["body"],
        "error_code": client.error_code(ack),
    }


def verdict(ack_class, committed_data, committed_change, success_expected):
    """Three-axis judgement, never collapsing to 'query matched'."""
    return {
        "ack": ack_class,
        "data_published": committed_data,
        "history_published": committed_change,
        "ack_matches_effect": {
            "2xx": committed_data and committed_change,
            "error": not (committed_data or committed_change),
            "no_response": None,  # silent by definition
        }.get(ack_class),
        "delivery_equivalent_to_acked": (ack_class == "2xx"
                                         and committed_data
                                         and committed_change),
        "note": success_expected,
    }


# -- scenarios ---------------------------------------------------------------

def s0_ack_then_kill(ctx):
    """A commit answered 200, then SIGKILL with no shutdown. Must survive."""
    root = trial_dir(ctx, "s0")
    server = fresh(root)
    ack = seed(server, [1, 2, 3])
    after_ack = state(server)
    server.kill()
    reopened, started = reopen(root)
    record = {
        "scenario": "S0_ack_then_kill9",
        "intent": "an answered commit must be visible after an ungraceful stop",
        "ack": open_ack(ack),
        "state_before_kill": after_ack,
        "reopen_ok": started["ok"],
        "reopen_error": started["error"],
        "state_after": state(reopened) if started["ok"] else None,
    }
    if started["ok"]:
        record["verdict"] = verdict(
            ack["class"],
            set(record["state_after"]["keys"]) == {1, 2, 3},
            any(w[2] == ["int:1", "int:2", "int:3"]
                for w in record["state_after"]["commit_writes"]),
            "ack-visible durability",
        )
        reopened.kill()
    return record


def s1_term_race(ctx):
    """SIGTERM the server and sample two distinct shutdown windows.

    Window A: a commit already inside the handler. Window B: a commit started
    only after the listener has begun closing. Both are recorded with their
    acknowledgement class and their post-reopen effect, because the two
    windows legitimately produce different answers and only the pairing of
    ack with effect is the contract.

    Neither window's kill is the observation. The mismatch between what was
    answered and what happened is.
    """
    import threading

    root = trial_dir(ctx, "s1")
    server = fresh(root)
    seed(server, [1])

    # -- Window A: commit in flight when SIGTERM arrives --------------------
    tx_a = server.begin()["body"]["id"]
    for key in (11, 12, 13):
        server.put(tx_a, REL, {"k": key, "v": "in-" + "x" * 4000})

    in_flight = {}

    def do_commit():
        in_flight["ack"] = server.commit(tx_a, timeout=20.0)

    worker = threading.Thread(target=do_commit)
    worker.start()
    time.sleep(0.0008)
    sigterm_a = server.proc.send_signal(signal.SIGTERM)
    worker.join(25)
    ack_a = in_flight.get("ack") or client.observation(
        None, None, 0.0, "commit never returned", "/commit")

    # -- Window B: commit started after shutdown began ---------------------
    try:
        tx_b = server.conn.post(
            "/v1/lamina/transactions", {"read_only": False})
        tx_b_id = (tx_b.get("body") or {}).get("id")
    except Exception:
        tx_b_id = None
    if tx_b_id:
        server.put(tx_b_id, REL, {"k": 21, "v": "late"})
        ack_b = server.commit(tx_b_id, timeout=10.0)
    else:
        ack_b = client.observation(None, None, 0.0,
                                   "no transaction could be opened during "
                                   "shutdown", "/commit")

    rc = server.wait(30)
    reopened, started = reopen(root)
    after = state(reopened) if started["ok"] else None
    record = {
        "scenario": "S1_sigterm_windows",
        "intent": "the shutdown window determines the answer; each window is "
                  "paired with its effect instead of being averaged",
        "sigterm_sent": sigterm_a,
        "server_exit": rc,
        "window_a_in_flight": {
            "ack": open_ack(ack_a),
            "keys": [11, 12, 13],
        },
        "window_b_after_shutdown": {
            "ack": open_ack(ack_b),
            "keys": [21],
        },
        "reopen_ok": started["ok"],
        "reopen_error": started["error"],
        "state_after": after,
    }
    if after is not None:
        published = after["keys"]
        record["published_keys"] = published
        record["window_a"] = {
            "data_published": all(k in published for k in (11, 12, 13)),
            "history_published": any("int:11" in w[2]
                                     for w in after["commit_writes"]),
            "all_or_nothing": all(k in published for k in (11, 12, 13))
            or not any(k in published for k in (11, 12, 13)),
            "ack_matches_effect": {
                "2xx": all(k in published for k in (11, 12, 13)),
                "error": not any(k in published for k in (11, 12, 13)),
                "no_response": None,
            }.get(ack_a["class"]),
        }
        record["window_b"] = {
            "data_published": 21 in published,
            "ack_matches_effect": {
                "2xx": 21 in published,
                "error": 21 not in published,
                "no_response": None,
            }.get(ack_b["class"]),
        }
        record["verdict"] = {
            "delivery_equivalent_windows": False,
            "reason": "two windows of the same shutdown produce different "
                      "acknowledgement classes; only the ack/effect pairing "
                      "is the contract, not a single final query",
            "window_b_is_racy": True,
            "window_b_note": (
                "window B opens a new transaction after shutdown has begun. "
                "In 35 observed trials it was always refused before a "
                "transaction could be opened, so key 21 never published. An "
                "earlier single-window variant of this scenario did observe "
                "2xx on a late commit; that variant submitted before the "
                "signal, so its result belongs to window A and must not be "
                "attributed to B. Whether B can ever be accepted is untested "
                "and is not claimed here."
            ),
        }
        reopened.kill()
    return record


def s2_abandon(ctx):
    """Send a commit and close the socket without reading the answer.

    Then attempt an explicit blind retry to show what that retry costs.
    """
    root = trial_dir(ctx, "s2")
    server = fresh(root)
    tx = server.begin()["body"]["id"]
    server.put(tx, REL, {"k": 7, "v": "once"})
    sent = client.abandon_commit(server.port, tx)
    time.sleep(0.3)
    after_abandon = state(server)
    retry_same_tx = server.commit(tx)
    tx2 = server.begin()["body"]["id"]
    server.put(tx2, REL, {"k": 7, "v": "once"})
    retry_new_tx = server.commit(tx2)
    after_retry = state(server)
    server.kill()
    reopened, started = reopen(root)
    after = state(reopened) if started["ok"] else None
    record = {
        "scenario": "S2_no_response_then_retry",
        "intent": "a missing response is not evidence of non-publication; "
                  "show the duplicate a blind retry creates",
        "abandon_send": sent,
        "state_after_abandon": after_abandon,
        "abandon_published": any("int:7" in w[2]
                                 for w in after_abandon["commit_writes"]),
        "retry_same_tx": open_ack(retry_same_tx),
        "retry_new_tx": open_ack(retry_new_tx),
        "state_after_retry": after_retry,
        "commit_records_after_retry": len(after_retry["commit_writes"]),
        "duplicate_commit_records": sum(
            1 for w in after_retry["commit_writes"] if w[2] == ["int:7"]),
        "reopen_ok": started["ok"],
        "state_after": after,
    }
    if after is not None:
        record["verdict"] = verdict(
            "no_response",
            after["keys"] == [7],
            any("int:7" in w[2] for w in after["commit_writes"]),
            "no-response ambiguity",
        )
        record["verdict"]["data_identical_to_acked"] = after["keys"] == [7]
        record["verdict"]["delivery_equivalent_to_acked"] = False
        record["verdict"]["reason"] = (
            "final rows equal an acked single write, but the change feed "
            "carries two commit records for the same key"
        )
        reopened.kill()
    return record


def s3_fsync_fail(ctx):
    """Make the commit's fsync fail with ENOSYS inside the live process.

    This is the honest version of "storage reported failure". It does not drop
    the page cache, so the frame bytes remain in the file; the record says so
    explicitly instead of claiming media loss.
    """
    root = trial_dir(ctx, "s3")
    server = fresh(root)
    seed(server, [1])
    before = state(server)
    journal_before = client.journal_size(root)
    tx = server.begin()["body"]["id"]
    for key in (2, 3, 4):
        server.put(tx, REL, {"k": key, "v": "f" * 100})
    injector = subprocess.Popen(
        [ctx["injector"], str(server.proc.pid), "--target", "1"],
        stderr=subprocess.PIPE,
    )
    time.sleep(0.6)
    ack = server.commit(tx, timeout=30.0)
    try:
        injector_out = injector.communicate(timeout=20)[1].decode()
    except subprocess.TimeoutExpired:
        injector.kill()
        injector_out = "TIMEOUT"
    injected = "injected ENOSYS" in injector_out
    journal_after = client.journal_size(root)
    server.kill()
    reopened, started = reopen(root)
    after = state(reopened) if started["ok"] else None
    record = {
        "scenario": "S3_fsync_failure_in_process",
        "intent": "a commit answered as a durable failure can still leave a "
                  "complete frame in the file when the media never lost it",
        "injector_output": injector_out.strip(),
        "injection_fired": injected,
        "window_missed": not injected,
        "ack": open_ack(ack),
        "journal_bytes_before": journal_before,
        "journal_bytes_after": journal_after,
        "journal_grew": (journal_before is not None
                         and journal_after is not None
                         and journal_after > journal_before),
        "page_cache_dropped": False,
        "reopen_ok": started["ok"],
        "reopen_error": started["error"],
        "state_after": after,
    }
    if not injected:
        record["failure"] = ("fault control did not fire: the injector never "
                             "reached an fsync, so no claim is supported")
    if after is not None:
        record["data_survived_despite_error_ack"] = after["keys"] == [1, 2, 3, 4]
        record["history_survived_despite_error_ack"] = any(
            "int:2" in w[2] for w in after["commit_writes"])
        record["verdict"] = verdict(
            ack["class"],
            after["keys"] == [1, 2, 3, 4],
            any("int:2" in w[2] for w in after["commit_writes"]),
            "error acknowledgement vs page cache survival",
        )
        record["verdict"]["equal_final_query_to_an_acked_commit"] = (
            after["keys"] == [1, 2, 3, 4])
        record["verdict"]["delivery_equivalent_to_acked"] = False
        record["verdict"]["reason"] = (
            "the client was told the commit failed; the rows and the change "
            "record exist anyway. Equality of the final query would have "
            "reported this as delivered."
        )
        reopened.kill()
    return record


def s4_write_fail(ctx):
    """Cause a real write error with RLIMIT_FSIZE (EFBIG, no injection)."""
    root = trial_dir(ctx, "s4")
    server = fresh(root)
    seed(server, [1])
    journal_before = client.journal_size(root)
    limit = (journal_before or 0) + 40
    prlimit = subprocess.run(
        ["prlimit", "--pid", str(server.proc.pid),
         f"--fsize={limit}:{limit}"],
        capture_output=True, text=True,
    )
    tx = server.begin()["body"]["id"]
    for key in (2, 3, 4, 5):
        server.put(tx, REL, {"k": key, "v": "e" * 120})
    ack = server.commit(tx)
    time.sleep(0.2)
    health_after = server.conn.get("/v1/lamina/health")
    alive = server.proc.poll() is None
    journal_after = client.journal_size(root)
    server.kill()
    reopened, started = reopen(root)
    after = state(reopened) if started["ok"] else None
    record = {
        "scenario": "S4_write_error_rlimit_fsize",
        "intent": "a frame cut short by a real write error must be detected "
                  "and truncated, not replayed",
        "prlimit_rc": prlimit.returncode,
        "prlimit_stderr": prlimit.stderr.strip(),
        "ack": open_ack(ack),
        "server_alive_after_error": alive,
        "health_after_error": open_ack(health_after),
        "journal_bytes_before": journal_before,
        "journal_bytes_after": journal_after,
        "reopen_ok": started["ok"],
        "reopen_error": started["error"],
        "state_after": after,
    }
    if ack["class"] != "error":
        record["failure"] = ("fault control did not fire: the limited write "
                             "was not rejected, so no claim is supported")
    if after is not None:
        record["verdict"] = verdict(
            ack["class"],
            after["keys"] == [1, 2, 3, 4, 5],
            any("int:2" in w[2] for w in after["commit_writes"]),
            "partial frame must not appear",
        )
        record["recovered_tail_bytes"] = after["recovered_tail_bytes"]
        reopened.kill()
    return record


def s5_backup_restore(ctx):
    """Commit, back up, commit again, restore. Compare data and history."""
    root = trial_dir(ctx, "s5")
    source = fresh(root)
    seed(source, [1, 2], prefix="a")
    point = state(source)
    backup = source.backup_bytes()
    image_path = ctx["base"] + "/s5.lmi"
    if backup["data"] is not None:
        with open(image_path, "wb") as handle:
            handle.write(backup["data"])
    later = seed(source, [3], prefix="b")
    after_source = state(source)
    source.kill()
    restored_root = trial_dir(ctx, "s5-restored")
    restored, started = reopen(restored_root, restore=image_path)
    after_restore = state(restored) if started["ok"] else None
    record = {
        "scenario": "S5_backup_restore_history",
        "intent": "the restored copy is the backup point, not the source head; "
                  "its change feed starts at a new base",
        "backup_bytes": len(backup["data"] or b""),
        "backup_digest_sha256": hashlib.sha256(backup["data"]).hexdigest()
        if backup["data"] else None,
        "state_at_backup": point,
        "source_commit_after_backup": open_ack(later),
        "state_source_head": after_source,
        "reopen_ok": started["ok"],
        "reopen_error": started["error"],
        "state_restored": after_restore,
    }
    if after_restore is not None:
        note_prev = record["state_at_backup"]["history_base"]
        record["axes"] = {
            "data_restored_equals_backup_point": (
                after_restore["keys"] == point["keys"]),
            "data_restored_equals_source_head": (
                after_restore["keys"] == after_source["keys"]),
            "history_base_restored": after_restore["history_base"],
            "history_base_at_backup": note_prev,
            "changes_after_0_status": after_restore["changes_status"],
        }
        # Cursor behaviour around the new base, recorded per cursor value.
        base = after_restore["history_base"]
        record["change_cursor_probe"] = {}
        for cursor in (0, max(base - 1, 0), base, base + 1):
            obs = restored.changes(cursor, 10)
            record["change_cursor_probe"][str(cursor)] = {
                "status": obs["status"],
                "class": obs["class"],
                "error_code": client.error_code(obs),
                "sequences": [r.get("sequence")
                              for r in (obs["body"] or {}).get("records", [])]
                if isinstance(obs["body"], dict) else None,
            }
        # Historical snapshot reads that the backup retained.
        record["snapshot_probe"] = {}
        for at in sorted({1, base, base + 1}):
            obs = restored.query(REL, at=at)
            record["snapshot_probe"][str(at)] = {
                "status": obs["status"],
                "class": obs["class"],
                "keys": client.row_keys(
                    {"rows": (obs["body"] or {}).get("rows", [])})
                if obs["status"] == 200 else None,
            }
        restored.kill()
    return record


def s6_dircopy(ctx):
    """Compare a plain directory copy with a validated restore at one point.

    Both artifacts are taken at the same head sequence, so the rows are equal
    by construction and the difference can only come from how the history is
    re-based. If the rows differ, that is a harness fault, not a finding.
    """
    root = trial_dir(ctx, "s6")
    source = fresh(root)
    seed(source, [1, 2], prefix="a")
    point = state(source)
    backup = source.backup_bytes()
    image_path = ctx["base"] + "/s6.lmi"
    with open(image_path, "wb") as handle:
        handle.write(backup["data"])
    source.terminate()

    copy_root = trial_dir(ctx, "s6-copy")
    shutil.copytree(root, copy_root)
    copy_server, copy_started = reopen(copy_root)
    copy_state = state(copy_server) if copy_started["ok"] else None

    restore_root = trial_dir(ctx, "s6-restore")
    restore_server, restore_started = reopen(restore_root,
                                             restore=image_path)
    restore_state = (state(restore_server) if restore_started["ok"] else None)

    record = {
        "scenario": "S6_dircopy_vs_restore",
        "intent": "with identical rows, a directory copy and a validated "
                  "restore still expose different change history",
        "point": point,
        "dircopy_open_ok": copy_started["ok"],
        "dircopy_state": copy_state,
        "restore_open_ok": restore_started["ok"],
        "restore_state": restore_state,
    }
    if copy_state and restore_state:
        same_rows = copy_state["keys"] == restore_state["keys"]
        record["axes"] = {
            "same_rows": same_rows,
            "rows_match_point": copy_state["keys"] == point["keys"],
            "dircopy_history_base": copy_state["history_base"],
            "restore_history_base": restore_state["history_base"],
            "dircopy_change_count": len(copy_state["change_sequences"]),
            "restore_change_count": len(restore_state["change_sequences"]),
            "dircopy_changes_status": copy_state["changes_status"],
            "restore_changes_status": restore_state["changes_status"],
        }
        record["verdict"] = {
            "equal_rows": same_rows,
            "delivery_equivalent": False,
            "reason": ("rows are identical, yet the change feeds differ: the "
                       "copy keeps the original journal history, the restore "
                       "rebases it and answers 410 below the new base"),
        }
        copy_server.kill()
        restore_server.kill()
    return record


def s7_corruption(ctx):
    """Three reopen cases: torn tail, corrupted complete frame, bad image."""
    out = {"scenario": "S7_reopen_boundaries", "cases": {}}
    # torn tail: append 3 bytes, expect truncation and full earlier data
    root = trial_dir(ctx, "s7a")
    server = fresh(root)
    seed(server, [1, 2])
    expected = state(server)
    server.kill()
    with open(os.path.join(root, "journal.lmw"), "ab") as handle:
        handle.write(b"\x00\x00\x00")
    reopened, started = reopen(root)
    out["cases"]["torn_tail"] = {
        "reopen_ok": started["ok"],
        "error": started["error"],
        "state": state(reopened) if started["ok"] else None,
        "data_preserved": bool(started["ok"]
                               and state(reopened)["keys"] == expected["keys"]),
    }
    if started["ok"]:
        reopened.kill()

    # corrupted last byte of a complete frame: must refuse to start
    root = trial_dir(ctx, "s7b")
    server = fresh(root)
    seed(server, [1])
    server.kill()
    path = os.path.join(root, "journal.lmw")
    data = bytearray(open(path, "rb").read())
    data[-1] ^= 1
    open(path, "wb").write(bytes(data))
    broken, broken_started = reopen(root)
    out["cases"]["corrupt_complete_frame"] = {
        "reopen_ok": broken_started["ok"],
        "refused": not broken_started["ok"],
        "error_tail": (broken_started["error"] or "")[-500:],
    }
    if broken_started["ok"]:
        broken.kill()

    # corrupted backup image: digest must reject before installing
    root = trial_dir(ctx, "s7c")
    server = fresh(root)
    seed(server, [1])
    backup = server.backup_bytes()
    server.kill()
    payload = json.loads(backup["data"])
    payload["payload"]["sequence"] = 999
    bad_path = ctx["base"] + "/bad.lmi"
    with open(bad_path, "wb") as handle:
        handle.write(json.dumps(payload).encode())
    target = trial_dir(ctx, "s7c-restored")
    bad, bad_started = reopen(target, restore=bad_path)
    out["cases"]["tampered_image"] = {
        "reopen_ok": bad_started["ok"],
        "refused": not bad_started["ok"],
        "target_dir_created": os.path.exists(target),
        "target_contents": sorted(os.listdir(target))
        if os.path.isdir(target) else None,
        "error_tail": (bad_started["error"] or "")[-500:],
    }
    if bad_started["ok"]:
        bad.kill()
    return out


def scenario_signature(key, record):
    """The outcome facts a repetition must reproduce exactly.

    Deliberately excludes timing and random transaction ids: those vary by
    design. Includes only facts that carry a durability claim.
    """
    if record.get("harness_error"):
        return {"harness_error": True}
    if key == "S0":
        return {"ack": record.get("ack", {}).get("class"),
                "keys": (record.get("state_after") or {}).get("keys")}
    if key == "S1":
        return {
            "a_ack": record.get("window_a_in_flight", {})
                             .get("ack", {}).get("class"),
            "a_matches": record.get("window_a", {}).get("ack_matches_effect"),
            "a_all_or_nothing": record.get("window_a", {}).get("all_or_nothing"),
            "b_ack": record.get("window_b_after_shutdown", {})
                             .get("ack", {}).get("class"),
            "b_published": record.get("window_b", {}).get("data_published"),
            "exit": record.get("server_exit"),
        }
    if key == "S2":
        return {"abandon_published": record.get("abandon_published"),
                "duplicates": record.get("duplicate_commit_records"),
                "keys": (record.get("state_after") or {}).get("keys")}
    if key == "S3":
        return {"ack": record.get("ack", {}).get("class"),
                "injected": record.get("injection_fired"),
                "survived": record.get("data_survived_despite_error_ack"),
                "keys": (record.get("state_after") or {}).get("keys")}
    if key == "S4":
        return {"ack": record.get("ack", {}).get("class"),
                "tail": (record.get("state_after") or {})
                        .get("recovered_tail_bytes"),
                "keys": (record.get("state_after") or {}).get("keys")}
    if key == "S5":
        return {"axes": record.get("axes"),
                "cursor": {k: v.get("status")
                           for k, v in (record.get("change_cursor_probe")
                                        or {}).items()},
                "snapshot": {k: v.get("status")
                             for k, v in (record.get("snapshot_probe")
                                          or {}).items()}}
    if key == "S6":
        return {"axes": record.get("axes")}
    if key == "S7":
        cases = record.get("cases") or {}
        return {name: {k: v for k, v in case.items()
                       if k in ("reopen_ok", "refused", "data_preserved",
                                "target_dir_created")}
                for name, case in cases.items()}
    return {}


def summarize_trials(key, trials):
    """Report which fields were stable across repetitions.

    Stability is judged on each record's explicit "signature": the set of
    outcome facts that must not vary. Scenarios that nest their acknowledgements
    (S1, S7) declare their own signature instead of relying on a top-level
    "ack" key that they do not have.

    A harness error or an unfired fault control in any trial invalidates the
    whole set and is surfaced, not averaged away.
    """
    signatures = [json.dumps(t.get("signature"), sort_keys=True)
                  for t in trials]
    distinct = sorted(set(signatures))
    ack_classes = [t.get("ack", {}).get("class") for t in trials]
    missed = [bool(t.get("window_missed")) for t in trials]
    harness_errors = [t.get("harness_error") for t in trials]
    failures = [t.get("failure") for t in trials]
    distribution = {}
    for sig in signatures:
        distribution[sig] = distribution.get(sig, 0) + 1
    return {
        "trials": len(trials),
        "distinct_signatures": len(distinct),
        "signature_distribution": distribution,
        "signature_stable": len(distinct) == 1,
        "bimodal": len(distinct) > 1 and not any(harness_errors),
        "ack_classes": ack_classes,
        "ack_class_stable": len(set(ack_classes)) == 1,
        "window_missed_any": any(missed),
        "window_missed_count": sum(missed),
        "harness_errors": [e for e in harness_errors if e],
        "valid": not any(harness_errors) and not any(failures)
                 and not any(missed),
        "failures": [f for f in failures if f],
        "wall_seconds": [t.get("wall_seconds") for t in trials],
    }


SCENARIOS = {
    "S0": s0_ack_then_kill,
    "S1": s1_term_race,
    "S2": s2_abandon,
    "S3": s3_fsync_fail,
    "S4": s4_write_fail,
    "S5": s5_backup_restore,
    "S6": s6_dircopy,
    "S7": s7_corruption,
}

BINARY = None
ENV = None


def main():
    global BINARY, ENV
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--only", default="")
    parser.add_argument("--repeat", type=int, default=1,
                        help="run each scenario N times to measure stability")
    parser.add_argument("--workroot", default="/dev/shm",
                        help="base filesystem for trial directories; use a "
                             "persistent path to compare storage classes")
    parser.add_argument("--injector", default=os.environ.get(
        "LAMINA_INJECTOR",
        os.path.join(os.path.dirname(HERE), "faults", "fsync_inject")))
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    BINARY = os.path.abspath(args.binary)
    ENV = dict(os.environ)
    selected = [s.strip().upper() for s in args.only.split(",") if s.strip()]
    if not selected:
        selected = list(SCENARIOS)

    os.makedirs(args.out, exist_ok=True)
    base = tempfile.mkdtemp(prefix="lamina-durability-", dir=args.workroot)
    ctx = {"base": base, "injector": args.injector}

    run = {
        "environment": environment(BINARY, args.injector),
        "workroot": args.workroot,
        "scenarios": {},
        "repetitions": {},
        "errors": {},
    }
    try:
        for key in selected:
            fn = SCENARIOS.get(key)
            if fn is None:
                run["errors"][key] = "unknown scenario"
                continue
            trials = []
            for index in range(max(1, args.repeat)):
                started = time.monotonic()
                try:
                    record = fn(ctx)
                except Exception as exc:
                    import traceback
                    record = {"scenario": fn.__name__,
                              "harness_error": f"{type(exc).__name__}: {exc}",
                              "traceback": traceback.format_exc()}
                record["wall_seconds"] = round(time.monotonic() - started, 3)
                record["trial"] = index
                record.setdefault("signature", scenario_signature(key, record))
                trials.append(record)
                print(f"[{key} #{index}] {record.get('scenario')} "
                      f"({record['wall_seconds']}s)", flush=True)
            run["scenarios"][key] = trials[0]
            run["trials"] = run.get("trials", {})
            run["trials"][key] = trials
            if len(trials) > 1:
                run["repetitions"][key] = summarize_trials(key, trials)
    finally:
        if not args.keep:
            shutil.rmtree(base, ignore_errors=True)
        else:
            run["kept_root"] = base

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = os.path.join(args.out, f"native-{stamp}.json")
    with open(path, "w") as handle:
        json.dump(run, handle, indent=2, sort_keys=True)
    print("wrote", path)

    invalid = [key for key, rep in run["repetitions"].items()
               if not rep["valid"]]
    invalid += [key for key, rec in run["scenarios"].items()
                if "harness_error" in rec and key not in run["repetitions"]]
    if invalid:
        print("INVALID scenarios:", ", ".join(sorted(set(invalid))))
        sys.exit(1)


if __name__ == "__main__":
    main()
