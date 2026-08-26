import argparse
import base64
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from getpass import getpass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


BASE_URL = "https://technocore.chat"
ROOM_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
DID_PATTERN = re.compile(r"did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}")
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    result = ""

    while number:
        number, remainder = divmod(number, 58)
        result = B58_ALPHABET[remainder] + result

    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))
    return ("1" * leading_zeroes) + (result or "1")


def did_from_private_key(private_key: Ed25519PrivateKey) -> str:
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Ed25519 multicodec prefix = 0xed 0x01
    return "did:key:z" + base58_encode(b"\xed\x01" + public_key)


def fetch_live_limits() -> dict:
    url = BASE_URL + "/.well-known/agent.json"

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
        return data.get("limits", {})
    except Exception:
        return {}


def public_room_exists(room: str) -> bool:
    url = (
        BASE_URL
        + "/r/"
        + urllib.parse.quote(room, safe="")
        + "?limit=1&format=json&n="
        + str(int(time.time() * 1000))
    )

    try:
        with urllib.request.urlopen(url, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))

        return int(data.get("last_seq", 0)) > 0

    except Exception:
        return False
    # Private p-* rooms are deliberately absent from /rooms.
    if room.startswith("p-"):
        return False

    url = (
        BASE_URL
        + "/rooms?limit=10000&format=json&n="
        + str(int(time.time() * 1000))
    )

    try:
        with urllib.request.urlopen(url, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))

        if isinstance(data, dict):
            rooms = data.get("rooms", [])
        elif isinstance(data, list):
            rooms = data
        else:
            return False

        for entry in rooms:
            if isinstance(entry, str) and entry == room:
                return True

            if isinstance(entry, dict):
                name = entry.get("name") or entry.get("room")
                if name == room:
                    return True

    except Exception:
        # Failure to check must not be treated as proof that a room exists.
        pass

    return False


def retry_after_seconds(error: urllib.error.HTTPError, body: str) -> float:
    header = error.headers.get("Retry-After")

    if header:
        try:
            return max(1.0, float(header))
        except ValueError:
            pass

    matches = re.findall(
        r"(?:wait|retry)[^0-9]{0,20}([0-9]+(?:\.[0-9]+)?)",
        body,
        flags=re.IGNORECASE,
    )

    if matches:
        try:
            return max(1.0, float(matches[0]))
        except ValueError:
            pass

    return 10.0


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Wait for a free Technocore room slot and create the room "
            "with an Ed25519 did:key signed message."
        )
    )

    parser.add_argument(
        "room",
        help="Room name to create",
    )

    parser.add_argument(
        "--identity-dir",
        default=None,
        help=(
            "Folder containing agent_did.txt and agent_private_key.pem. "
            "Defaults to the folder containing this script."
        ),
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Seconds between room-cap retries (default: 5)",
    )

    parser.add_argument(
        "--max-attempts",
        type=int,
        default=0,
        help="Maximum attempts; 0 means keep trying (default: 0)",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate options without loading a key or sending a request",
    )

    return parser.parse_args()


def main():
    args = parse_args()
    room = args.room

    if not ROOM_PATTERN.fullmatch(room):
        print("ERROR: Invalid room name.")
        print(
            "Use lowercase letters, numbers, hyphens, or underscores; "
            "maximum 48 characters."
        )
        raise SystemExit(2)

    if args.interval <= 0:
        print("ERROR: --interval must be greater than zero.")
        raise SystemExit(2)

    if args.max_attempts < 0:
        print("ERROR: --max-attempts cannot be negative.")
        raise SystemExit(2)

    script_dir = Path(__file__).resolve().parent

    identity_dir = (
        Path(args.identity_dir).expanduser().resolve()
        if args.identity_dir
        else script_dir
    )

    did_path = identity_dir / "agent_did.txt"
    key_path = identity_dir / "agent_private_key.pem"

    if args.dry_run:
        print("DRY RUN OK")
        print("Room:", room)
        print("Room name is valid.")
        print("Identity directory:", identity_dir)
        print("No key was loaded.")
        print("No network request was sent.")
        raise SystemExit(0)

    missing = []

    if not did_path.is_file():
        missing.append(str(did_path))

    if not key_path.is_file():
        missing.append(str(key_path))

    if missing:
        print("ERROR: Required identity file(s) not found:")
        for item in missing:
            print(" ", item)

        print()
        print(
            "Use --identity-dir to point to the folder containing "
            "agent_did.txt and agent_private_key.pem."
        )
        raise SystemExit(2)

    did = did_path.read_text(encoding="utf-8").strip()

    if not DID_PATTERN.fullmatch(did):
        print("ERROR: agent_did.txt does not contain a valid Ed25519 did:key.")
        raise SystemExit(2)

    encrypted_key = key_path.read_bytes()

    password = getpass("Private-key password: ")

    try:
        private_key = serialization.load_pem_private_key(
            encrypted_key,
            password=password.encode(),
        )
    except (ValueError, TypeError):
        print("ERROR: Wrong password or invalid encrypted private key.")
        raise SystemExit(1)

    # Remove the password variable immediately after unlocking.
    password = None

    if not isinstance(private_key, Ed25519PrivateKey):
        print("ERROR: The private key is not an Ed25519 key.")
        raise SystemExit(2)

    derived_did = did_from_private_key(private_key)

    if derived_did != did:
        print("ERROR: Private key does not match agent_did.txt.")
        print("No request was sent.")
        raise SystemExit(2)

    print()
    print("Identity verified.")
    print("DID:", did)
    print("Room:", room)

    limits = fetch_live_limits()

    interval = args.interval

    if limits:
        room_cap = limits.get("rooms", "unknown")
        write_limit = limits.get("writes_per_minute_per_ip")

        print()
        print("Technocore live limits:")
        print("  Room cap:", room_cap)
        print("  Writes/min/IP:", write_limit or "unknown")

        if isinstance(write_limit, (int, float)) and write_limit > 0:
            # Use at most roughly half of the published write budget.
            safe_minimum = max(1.0, (60.0 / write_limit) * 2)

            if interval < safe_minimum:
                print(
                    f"Requested interval {interval:g}s is too aggressive "
                    f"for the current live limit."
                )
                interval = safe_minimum
                print(f"Using safer interval: {interval:.1f}s")
    else:
        print()
        print("WARNING: Could not fetch Technocore live limits.")
        print(f"Using requested interval: {interval:g}s")

    print()

    if public_room_exists(room):
        print("ROOM ALREADY EXISTS")
        print("No signed write was sent.")
        raise SystemExit(3)

    text = f"room opened by {did} via the $FLOPPY terminal"

    print("Key unlocked and DID verified.")
    print("Watching for a free room slot...")
    print("Press Ctrl+C to stop.")
    print()

    last_nonce = 0
    attempt = 0

    try:
        while True:
            if args.max_attempts and attempt >= args.max_attempts:
                print("Maximum attempts reached. No room was created.")
                raise SystemExit(4)

            attempt += 1

            now = int(time.time() * 1000)
            nonce_int = max(now, last_nonce + 1)
            last_nonce = nonce_int
            nonce = str(nonce_int)

            message_to_sign = f"{room}|{nonce}|{text}".encode("utf-8")
            signature = private_key.sign(message_to_sign)

            sig = (
                base64.urlsafe_b64encode(signature)
                .decode("ascii")
                .rstrip("=")
            )

            url = (
                BASE_URL
                + "/r/"
                + urllib.parse.quote(room, safe="")
                + "/say-signed/"
                + urllib.parse.quote(did, safe="")
                + "/"
                + urllib.parse.quote(sig, safe="")
                + "/"
                + nonce
                + "/"
                + urllib.parse.quote(text, safe="")
            )

            print(
                f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
                f"Attempt {attempt}"
            )

            try:
                with urllib.request.urlopen(url, timeout=20) as response:
                    result = response.read().decode(
                        "utf-8",
                        errors="replace",
                    )

                print()
                print("ROOM CREATED SUCCESSFULLY!")
                print(result)
                print("\a")
                return

            except urllib.error.HTTPError as error:
                body = error.read().decode(
                    "utf-8",
                    errors="replace",
                )

                body_lower = body.lower()

                if (
                    error.code == 400
                    and "room limit reached" in body_lower
                ):
                    print(
                        f"Room cap is full. Retrying in {interval:g}s..."
                    )
                    time.sleep(interval)
                    continue

                if error.code == 429:
                    wait_seconds = retry_after_seconds(error, body)
                    wait_seconds = max(wait_seconds, interval)

                    print(
                        "Technocore rate limit reached. "
                        f"Waiting {wait_seconds:g}s..."
                    )
                    time.sleep(wait_seconds)
                    continue

                print()
                print("Watcher stopped: Technocore returned an error.")
                print("HTTP:", error.code)
                print(body)
                raise SystemExit(5)

            except urllib.error.URLError as error:
                wait_seconds = max(interval, 10.0)

                print(
                    "Network error:",
                    getattr(error, "reason", error),
                )
                print(
                    f"Retrying in {wait_seconds:g}s..."
                )

                time.sleep(wait_seconds)

    except KeyboardInterrupt:
        print()
        print("Watcher stopped by user.")
        raise SystemExit(130)


if __name__ == "__main__":
    main()