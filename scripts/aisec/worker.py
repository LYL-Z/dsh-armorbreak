#!/usr/bin/env python3
"""ArmorBreak AISEC worker: newline-delimited JSON over stdio, stdlib only."""
import json
import os
import sys
import time

PROTOCOL = "armorbreak.aisec-worker/v1"


def respond(payload):
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            request_id = request.get("id")
            method = request.get("method")
            params = request.get("params") or {}
            if method == "ping":
                respond({"id": request_id, "ok": True, "result": {"protocol": PROTOCOL, "pid": os.getpid()}})
            elif method == "env":
                respond({"id": request_id, "ok": True, "result": sorted(os.environ.keys())})
            elif method == "evaluate":
                prompt = str(params.get("prompt", ""))
                safe = "ignore previous instructions" not in prompt.lower()
                respond({"id": request_id, "ok": True, "result": {"verdict": "PASS" if safe else "FAIL", "output": "mock worker response"}})
            elif method == "sleep":
                time.sleep(float(params.get("seconds", 1)))
                respond({"id": request_id, "ok": True, "result": {"slept": params.get("seconds", 1)}})
            elif method == "crash":
                os._exit(7)
            elif method == "shutdown":
                respond({"id": request_id, "ok": True, "result": {"shutdown": True}})
                return 0
            else:
                respond({"id": request_id, "ok": False, "error": {"code": "UNKNOWN_METHOD", "message": str(method)}})
        except Exception as exc:  # noqa: BLE001 - worker must return an error, not die
            respond({"id": None, "ok": False, "error": {"code": "BAD_REQUEST", "message": str(exc)}})
    return 0


if __name__ == "__main__":
    sys.exit(main())
