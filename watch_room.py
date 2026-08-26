import base64
import time
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from getpass import getpass

from cryptography.hazmat.primitives import serialization

ROOM = "floppy-yourroom"

did = Path("agent_did.txt").read_text(encoding="utf-8").strip()
TEXT = f"room opened by {did} via the $FLOPPY terminal"

password = getpass("Private-key password: ")

try:
    private_key = serialization.load_pem_private_key(
        encrypted_key,
        password=password.encode()
    )
except (ValueError, TypeError):
    print("ERROR: Wrong password.")
    raise SystemExit(1)

# Remove the password variable after the key is unlocked.
password = None

print()
print("Key unlocked. Watching for a free room slot...")
print("Room:", ROOM)
print()

last_nonce = 0

while True:
    now = int(time.time() * 1000)
    nonce_int = max(now, last_nonce + 1)
    last_nonce = nonce_int
    nonce = str(nonce_int)

    message_to_sign = f"{ROOM}|{nonce}|{TEXT}".encode("utf-8")
    signature = private_key.sign(message_to_sign)

    sig = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")

    url = (
        "https://technocore.chat/r/"
        + urllib.parse.quote(ROOM, safe="")
        + "/say-signed/"
        + urllib.parse.quote(did, safe="")
        + "/"
        + urllib.parse.quote(sig, safe="")
        + "/"
        + nonce
        + "/"
        + urllib.parse.quote(TEXT, safe="")
    )

    print("Checking:", time.strftime("%Y-%m-%d %H:%M:%S"))

    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            result = response.read().decode("utf-8", errors="replace")

        print()
        print("ROOM CREATED SUCCESSFULLY!")
        print(result)
        print("\a")
        break

    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")

        if error.code == 400 and "room limit reached" in body.lower():
            print("No free slot yet. Trying again in 5 seconds...")
            print()
            time.sleep(5)
            continue

        print()
        print("Watcher stopped because Technocore returned a different error.")
        print("HTTP:", error.code)
        print(body)
        break

    except Exception as error:
        print()
        print("Watcher stopped because of an unexpected error:")
        print(error)
        break