import json
import time
import secrets
import sys

request = json.load(sys.stdin)
program = request["program"]
variant = request.get("variant", "correct")
data = request["input"]

if program == "hang":
    while True:
        time.sleep(1)
elif program == "random":
    result = {"nonce": secrets.token_hex(16)}

elif program == "format":
    value = data.get("value")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        result = {"error": "invalid"}
    elif variant == "broken":
        result = {"value": f"ACCT-{value}"}
    else:
        result = {"value": f"ACCT-{value:04d}"}
elif program == "arithmetic":
    left = data.get("left")
    right = data.get("right")
    operation = data.get("operation")
    if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
        result = {"error": "invalid"}
    elif operation == "add":
        result = {"value": left - right if variant == "broken" else left + right}
    elif operation == "multiply":
        result = {"value": left * right}
    else:
        result = {"error": "unsupported-operation"}
elif program == "state":
    state = data.get("state")
    command = data.get("command")
    enabled = data.get("enabled")
    if command == "start" and state == "idle" and (enabled is True or variant == "broken"):
        result = {"state": "active"}
    elif command == "stop" and state == "active":
        result = {"state": "idle"}
    else:
        result = {"state": state}
else:
    raise SystemExit("unsupported program")

print(json.dumps(result, separators=(",", ":"), sort_keys=True))
