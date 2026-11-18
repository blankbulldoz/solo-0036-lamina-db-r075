#!/usr/bin/env python3
"""Container-environment arm of the LaminaDB durability comparison.

STATUS IN THIS WORKSPACE: NOT EXECUTED.

The build environment had no container runtime of any kind:

    docker CLI          absent
    podman CLI          absent
    docker.sock         absent
    /run/containerd     absent
    unshare -Ur         "Operation not permitted"
    capabilities        CapEff=0  (no CAP_SYS_ADMIN)
    /dev/fuse           absent

Executing this file here would not compare native with container. It would
compare nothing with nothing and then print JSON that looks like evidence.
The script therefore refuses to produce a result unless it can prove a real
runtime is present, and the accompanying report marks the container column
as unmeasured rather than assumed equal.

Why the runtime matters for this specific question: the durability boundary
is about fsync reaching stable storage. A container does not change that
syscall's meaning, but it does change which filesystem and which storage
stack sit underneath it (overlayfs upper layer, a bind mount, a named
volume, a virtiofs share, a network volume). Two things must be recorded
separately, because only the first is a product property:

  1. acknowledgement semantics  (product):  the three observation classes
  2. storage latency/durability  (environment): fs type, fsync cost, whether
     the volume survives container replacement

This arm records both, and never merges them into "container equals native".

Protocol (identical scenario set to the native arm, same harness code):

    docker build -t lamina-db .
    docker run --rm -v lamina-volume:/data ...
    python3 -I container_arm.py --image lamina-db --volume lamina-volume

The required measurements are listed in PROTOCOL below. Each one has an
explicit "what would overturn the native conclusion" clause.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "harness"))

PROTOCOL = {
    "purpose": "separate product acknowledgement semantics from container "
               "storage behaviour; do not assume equivalence",
    "shared_code": "../harness/experiments.py (same scenarios, same classes)",
    "steps": [
        {
            "id": "C1_runtime_probe",
            "action": "docker info; record storage driver, cgroup version, "
                      "server version",
            "overturns_native_if": "no runtime is available (then the "
                                   "container column stays unmeasured)",
        },
        {
            "id": "C2_fs_probe",
            "action": "run `stat -f -c %T /data` inside the container and "
                      "record the driver behind the volume",
            "overturns_native_if": "the volume is not a local fsync-capable "
                                   "filesystem; fsync may be a no-op or a "
                                   "network round trip, which changes the "
                                   "latency distribution but not the "
                                   "acknowledgement contract",
        },
        {
            "id": "C3_ack_matrix",
            "action": "run S0, S1, S2, S3, S4, S5, S6, S7 from experiments.py "
                      "against the container endpoint",
            "overturns_native_if": "any scenario reports a different "
                                   "observation class for the same injected "
                                   "fault (for example a 503 that becomes "
                                   "200, or a no_response that becomes 2xx)",
        },
        {
            "id": "C4_volume_survival",
            "action": "commit, `docker rm -f`, re-run on the same named "
                      "volume, compare rows and /changes",
            "overturns_native_if": "a committed record is missing after "
                                   "container replacement while the volume "
                                   "was preserved (this is a volume problem, "
                                   "not a container-vs-native difference, "
                                   "and must be reported as such)",
        },
        {
            "id": "C5_restart_cost",
            "action": "measure cold start to /health for native and container "
                      "on the same image and data size",
            "overturns_native_if": "never on its own; start time is recorded "
                                   "but is not evidence of durability",
        },
    ],
    "explicitly_not_evidence": [
        "container starts slower or faster",
        "the same final query returns the same rows in both environments",
        "a modified binary or image was used to make the two match",
    ],
}


def probe_runtime():
    found = {}
    for name in ("docker", "podman", "nerdctl"):
        found[name] = shutil.which(name)
    found["docker_sock"] = os.path.exists("/var/run/docker.sock")
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="lamina-db")
    parser.add_argument("--volume", default="lamina-volume")
    parser.add_argument("--out", default="../evidence/container.json")
    parser.add_argument("--print-protocol", action="store_true")
    args = parser.parse_args()

    if args.print_protocol:
        print(json.dumps(PROTOCOL, indent=2))
        return

    runtime = probe_runtime()
    usable = bool(runtime.get("docker") or runtime.get("podman"))
    record = {
        "arm": "container",
        "status": None,
        "runtime_probe": runtime,
        "protocol": PROTOCOL,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if not usable:
        record["status"] = "not_executed"
        record["reason"] = (
            "no container runtime is present in this build environment; "
            "the container column is unmeasured, not equal to native"
        )
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w") as handle:
            json.dump(record, handle, indent=2, sort_keys=True)
        print("container arm NOT executed:", record["reason"])
        print("wrote", args.out)
        return

    record["status"] = "runtime_present_unimplemented"
    record["reason"] = (
        "a runtime exists but this environment was not provisioned for it; "
        "run the protocol steps against a real image before making any "
        "container claim"
    )
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
    print(record["reason"])


if __name__ == "__main__":
    main()
