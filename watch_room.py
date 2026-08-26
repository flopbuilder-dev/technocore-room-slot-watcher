import argparse
import base64
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


BASE_URL = "https://technocore.chat"
ROOM_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
DID_PATTERN = re.compile(r"did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}")
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {character: index for index, character in enumerate(B58_ALPHABET)}
WRITE_CONFIRMED = "confirmed"
ROOM_OCCUPIED = "occupied"
WRITE_ABSENT = "absent"
PROOF_SCHEMA = "technocore-contribution-proof/v1"
PROOF_ALGORITHM = "Ed25519"
COMMIT_PATTERN = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")


class RoomLookupError(RuntimeError):
    """Raised when Technocore room state cannot be confirmed safely."""


class ProofError(RuntimeError):
    """Raised when a contribution proof is invalid or cannot be created."""


class PublishUncertainError(RuntimeError):
    """Raised when a signed write may have succeeded but cannot be confirmed."""

    def __init__(self, room: str, nonce: str, text: str, reason: str):
        super().__init__(reason)
        self.room = room
        self.nonce = nonce
        self.text = text


def base58_encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    result = ""

    while number:
        number, remainder = divmod(number, 58)
        result = B58_ALPHABET[remainder] + result

    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))
    return ("1" * leading_zeroes) + (result or "1")


def base58_decode(value: str) -> bytes:
    if not value:
        raise ValueError("Base58 value is empty.")

    number = 0

    for character in value:
        try:
            digit = B58_INDEX[character]
        except KeyError as error:
            raise ValueError("Base58 value contains an invalid character.") from error

        number = (number * 58) + digit

    decoded = (
        number.to_bytes((number.bit_length() + 7) // 8, "big")
        if number
        else b""
    )
    leading_zeroes = len(value) - len(value.lstrip("1"))
    return (b"\x00" * leading_zeroes) + decoded


def did_from_private_key(private_key: Ed25519PrivateKey) -> str:
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Ed25519 multicodec prefix = 0xed 0x01
    return "did:key:z" + base58_encode(b"\xed\x01" + public_key)


def public_key_from_did(did: str) -> Ed25519PublicKey:
    if not isinstance(did, str) or not DID_PATTERN.fullmatch(did):
        raise ProofError("Proof contains an invalid Ed25519 did:key.")

    try:
        decoded = base58_decode(did.removeprefix("did:key:z"))
    except ValueError as error:
        raise ProofError(str(error)) from error

    if len(decoded) != 34 or decoded[:2] != b"\xed\x01":
        raise ProofError("Proof DID is not an Ed25519 did:key.")

    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def load_identity_files(identity_dir: Path) -> tuple[str, bytes]:
    did_path = identity_dir / "agent_did.txt"
    key_path = identity_dir / "agent_private_key.pem"
    missing = [str(path) for path in (did_path, key_path) if not path.is_file()]

    if missing:
        raise FileNotFoundError("; ".join(missing))

    did = did_path.read_text(encoding="utf-8").strip()

    if not DID_PATTERN.fullmatch(did):
        raise ProofError(
            "agent_did.txt does not contain a valid Ed25519 did:key."
        )

    return did, key_path.read_bytes()


def unlock_and_verify_identity(
    did: str,
    encrypted_key: bytes,
    password: str,
) -> Ed25519PrivateKey:
    try:
        private_key = serialization.load_pem_private_key(
            encrypted_key,
            password=password.encode(),
        )
    except (ValueError, TypeError) as error:
        raise ProofError(
            "Wrong password or invalid encrypted private key."
        ) from error

    if not isinstance(private_key, Ed25519PrivateKey):
        raise ProofError("The private key is not an Ed25519 key.")

    if did_from_private_key(private_key) != did:
        raise ProofError("Private key does not match agent_did.txt.")

    return private_key


def normalize_repository_url(repository: str) -> str:
    if not isinstance(repository, str):
        raise ProofError("Repository must be a public HTTPS URL.")

    value = repository.strip().rstrip("/")

    if value.endswith(".git"):
        value = value[:-4]

    parsed = urllib.parse.urlsplit(value)

    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ProofError(
            "Repository must be a public HTTPS URL without credentials, "
            "a query, or a fragment."
        )

    if not parsed.path.strip("/"):
        raise ProofError("Repository URL must include a repository path.")

    return value


def normalize_commit_hash(commit: str) -> str:
    if not isinstance(commit, str):
        raise ProofError("Commit hash must be a string.")

    value = commit.strip().lower()

    if not COMMIT_PATTERN.fullmatch(value):
        raise ProofError("Commit hash must contain exactly 40 or 64 hex characters.")

    return value


def commit_url_for(repository: str, commit: str) -> str:
    parsed = urllib.parse.urlsplit(repository)
    separator = "/-/commit/" if parsed.hostname == "gitlab.com" else "/commit/"
    return repository.rstrip("/") + separator + commit


def proof_core_fields(
    did: str,
    repository: str,
    commit: str,
    created_at: str,
) -> dict:
    return {
        "schema": PROOF_SCHEMA,
        "did": did,
        "repository": repository,
        "commit": commit,
        "commit_url": commit_url_for(repository, commit),
        "created_at": created_at,
    }


def canonical_proof_payload(core: dict) -> bytes:
    return json.dumps(
        core,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def base64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ProofError("Proof signature is missing.")

    padding = "=" * (-len(value) % 4)

    try:
        return base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as error:
        raise ProofError("Proof signature is not valid base64url.") from error


def proof_envelope_payload(document: dict) -> bytes:
    fields = (
        "schema",
        "did",
        "repository",
        "commit",
        "commit_url",
        "created_at",
        "signature_algorithm",
        "signature",
        "technocore",
    )
    envelope = {field: document[field] for field in fields}
    return canonical_proof_payload(envelope)


def seal_proof_document(
    document: dict,
    private_key: Ed25519PrivateKey,
) -> dict:
    document["record_signature"] = base64url_encode(
        private_key.sign(proof_envelope_payload(document))
    )
    return document


def create_proof_document(
    did: str,
    private_key: Ed25519PrivateKey,
    repository: str,
    commit: str,
    created_at: str | None = None,
) -> dict:
    repository = normalize_repository_url(repository)
    commit = normalize_commit_hash(commit)
    created_at = created_at or datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
    core = proof_core_fields(did, repository, commit, created_at)
    signature = private_key.sign(canonical_proof_payload(core))

    document = {
        **core,
        "signature_algorithm": PROOF_ALGORITHM,
        "signature": base64url_encode(signature),
        "technocore": None,
    }
    return seal_proof_document(document, private_key)


def verify_proof_document(document: dict) -> str:
    if not isinstance(document, dict):
        raise ProofError("Proof document must be a JSON object.")

    required = (
        "schema",
        "did",
        "repository",
        "commit",
        "commit_url",
        "created_at",
        "signature_algorithm",
        "signature",
        "technocore",
        "record_signature",
    )
    missing = [field for field in required if field not in document]

    if missing:
        raise ProofError("Proof is missing field(s): " + ", ".join(missing))

    unexpected = sorted(set(document) - set(required))

    if unexpected:
        raise ProofError(
            "Proof contains unexpected field(s): " + ", ".join(unexpected)
        )

    if document["schema"] != PROOF_SCHEMA:
        raise ProofError("Unsupported proof schema.")

    if document["signature_algorithm"] != PROOF_ALGORITHM:
        raise ProofError("Unsupported proof signature algorithm.")

    repository = normalize_repository_url(document["repository"])
    commit = normalize_commit_hash(document["commit"])
    expected_commit_url = commit_url_for(repository, commit)

    if document["repository"] != repository:
        raise ProofError("Proof repository URL is not canonical.")

    if document["commit"] != commit:
        raise ProofError("Proof commit hash is not canonical lowercase hex.")

    if document["commit_url"] != expected_commit_url:
        raise ProofError("Proof commit URL does not match its repository and commit.")

    created_at = document["created_at"]

    if not isinstance(created_at, str) or not created_at.endswith("Z"):
        raise ProofError("Proof created_at must be a UTC timestamp ending in Z.")

    try:
        parsed_created_at = datetime.fromisoformat(
            created_at.removesuffix("Z") + "+00:00"
        )
    except ValueError as error:
        raise ProofError("Proof created_at is not a valid timestamp.") from error

    if parsed_created_at.utcoffset() != timezone.utc.utcoffset(parsed_created_at):
        raise ProofError("Proof created_at must use UTC.")

    core = proof_core_fields(
        document["did"],
        repository,
        commit,
        created_at,
    )
    signature = base64url_decode(document["signature"])
    public_key = public_key_from_did(document["did"])

    try:
        public_key.verify(signature, canonical_proof_payload(core))
    except InvalidSignature as error:
        raise ProofError("Proof signature is invalid.") from error

    validate_technocore_record(document)
    record_signature = base64url_decode(document["record_signature"])

    try:
        public_key.verify(record_signature, proof_envelope_payload(document))
    except InvalidSignature as error:
        raise ProofError("Proof record signature is invalid.") from error

    return document["did"]


def fetch_live_limits() -> dict:
    url = BASE_URL + "/.well-known/agent.json"

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
        return data.get("limits", {})
    except Exception:
        return {}


def fetch_room_snapshot(room: str, limit: int = 200) -> dict:
    url = (
        BASE_URL
        + "/r/"
        + urllib.parse.quote(room, safe="")
        + f"?limit={limit}&format=json&n="
        + str(int(time.time() * 1000))
    )

    try:
        with urllib.request.urlopen(url, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (
        urllib.error.URLError,
        TimeoutError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as error:
        raise RoomLookupError(str(error)) from error

    if not isinstance(data, dict):
        raise RoomLookupError("Technocore returned an unexpected room response.")

    try:
        last_seq = int(data.get("last_seq", 0))
    except (TypeError, ValueError) as error:
        raise RoomLookupError(
            "Technocore returned an invalid last_seq value."
        ) from error

    messages = data.get("messages", [])

    if not isinstance(messages, list):
        raise RoomLookupError("Technocore returned an invalid messages value.")

    data["last_seq"] = last_seq
    return data


def public_room_exists(room: str) -> bool:
    return fetch_room_snapshot(room, limit=1)["last_seq"] > 0


def find_signed_message(
    snapshot: dict,
    did: str,
    nonce: str,
    text: str,
) -> dict | None:
    for message in snapshot["messages"]:
        if not isinstance(message, dict):
            continue

        if (
            message.get("from") == did
            and str(message.get("nonce")) == nonce
            and message.get("text") == text
        ):
            return message

    return None


def reconcile_ambiguous_write(
    room: str,
    did: str,
    nonce: str,
    text: str,
) -> str:
    snapshot = fetch_room_snapshot(room, limit=200)

    if find_signed_message(snapshot, did, nonce, text):
        return WRITE_CONFIRMED

    if snapshot["last_seq"] > 0:
        return ROOM_OCCUPIED

    return WRITE_ABSENT


def signed_write_url(
    room: str,
    did: str,
    private_key: Ed25519PrivateKey,
    nonce: str,
    text: str,
) -> str:
    message_to_sign = f"{room}|{nonce}|{text}".encode("utf-8")
    signature = private_key.sign(message_to_sign)
    sig = base64url_encode(signature)

    return (
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


def confirm_published_message(
    room: str,
    did: str,
    nonce: str,
    text: str,
) -> dict | None:
    snapshot = fetch_room_snapshot(room, limit=200)
    return find_signed_message(snapshot, did, nonce, text)


def publish_contribution_proof(
    room: str,
    did: str,
    private_key: Ed25519PrivateKey,
    text: str,
) -> dict:
    nonce = str(int(time.time() * 1000))
    url = signed_write_url(room, did, private_key, nonce, text)

    while True:
        try:
            with urllib.request.urlopen(url, timeout=20) as response:
                response.read()
            break
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")

            if error.code == 429:
                wait_seconds = retry_after_seconds(error, body)
                print(
                    "Technocore rate limit reached. "
                    f"Waiting {wait_seconds:g}s..."
                )
                time.sleep(wait_seconds)
                continue

            raise ProofError(
                f"Technocore rejected the proof write with HTTP {error.code}: "
                + body
            ) from error
        except (urllib.error.URLError, TimeoutError) as error:
            for verification_attempt in range(1, 4):
                try:
                    message = confirm_published_message(
                        room,
                        did,
                        nonce,
                        text,
                    )
                except RoomLookupError:
                    if verification_attempt < 3:
                        time.sleep(5)
                    continue

                if message:
                    return {
                        "status": "confirmed-after-timeout",
                        "room": room,
                        "seq": message.get("seq"),
                        "nonce": nonce,
                        "timestamp": message.get("ts"),
                        "text": text,
                    }

                break

            raise PublishUncertainError(
                room,
                nonce,
                text,
                "The proof write may have succeeded, but it could not be "
                "confirmed. V3 did not resend it.",
            ) from error

    try:
        message = confirm_published_message(room, did, nonce, text)
    except RoomLookupError as error:
        raise PublishUncertainError(
            room,
            nonce,
            text,
            "Technocore accepted the request, but the stored message could not "
            "be read back. V3 did not resend it.",
        ) from error

    if not message:
        raise PublishUncertainError(
            room,
            nonce,
            text,
            "Technocore returned success, but the exact stored message was not "
            "found. V3 did not resend it.",
        )

    return {
        "status": "confirmed",
        "room": room,
        "seq": message.get("seq"),
        "nonce": nonce,
        "timestamp": message.get("ts"),
        "text": text,
    }


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


def proof_message_text(document: dict) -> str:
    return "Signed contribution proof: " + document["commit_url"]


def validate_technocore_record(document: dict) -> None:
    record = document.get("technocore")

    if record is None:
        return

    if not isinstance(record, dict):
        raise ProofError("Proof technocore record must be an object or null.")

    expected_fields = {
        "status",
        "room",
        "seq",
        "nonce",
        "timestamp",
        "text",
    }
    missing = sorted(expected_fields - set(record))
    unexpected = sorted(set(record) - expected_fields)

    if missing:
        raise ProofError(
            "Proof technocore record is missing field(s): " + ", ".join(missing)
        )

    if unexpected:
        raise ProofError(
            "Proof technocore record contains unexpected field(s): "
            + ", ".join(unexpected)
        )

    if record.get("status") not in {
        "confirmed",
        "confirmed-after-timeout",
        "uncertain",
    }:
        raise ProofError("Proof technocore status is invalid.")

    room = record.get("room")
    nonce = str(record.get("nonce", ""))

    if not isinstance(room, str) or not ROOM_PATTERN.fullmatch(room):
        raise ProofError("Proof technocore room is invalid.")

    if not nonce.isdigit():
        raise ProofError("Proof technocore nonce is invalid.")

    if record.get("text") != proof_message_text(document):
        raise ProofError("Proof technocore text does not match the commit URL.")

    if record["status"].startswith("confirmed"):
        try:
            sequence = int(record.get("seq"))
        except (TypeError, ValueError) as error:
            raise ProofError("Confirmed Technocore sequence is invalid.") from error

        if sequence <= 0:
            raise ProofError("Confirmed Technocore sequence must be positive.")

        if not isinstance(record["timestamp"], str) or not record["timestamp"]:
            raise ProofError("Confirmed Technocore timestamp is invalid.")
    elif record["seq"] is not None or record["timestamp"] is not None:
        raise ProofError(
            "Uncertain Technocore records cannot claim a sequence or timestamp."
        )


def write_output_file(path: Path, content: str, force: bool) -> None:
    if path.exists() and not force:
        raise ProofError(
            f"Output already exists: {path}. Use --force to replace it."
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_file.write(content)
            temporary_path = Path(temporary_file.name)

        if not force and path.exists():
            raise ProofError(
                f"Output already exists: {path}. Use --force to replace it."
            )

        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def evidence_text(document: dict) -> str:
    verify_proof_document(document)
    validate_technocore_record(document)
    record = document.get("technocore")
    lines = [
        "TECHNOCORE CONTRIBUTION PROOF",
        "",
        f"Schema: {document['schema']}",
        f"DID: {document['did']}",
        f"Repository: {document['repository']}",
        f"Commit: {document['commit']}",
        f"Commit URL: {document['commit_url']}",
        f"Created at: {document['created_at']}",
        f"Signature algorithm: {document['signature_algorithm']}",
        "Local signature: VALID",
        "Evidence-record signature: VALID",
    ]

    if record is None:
        lines.extend(
            [
                "",
                "Technocore publication: NOT REQUESTED",
            ]
        )
    else:
        lines.extend(
            [
                "",
                f"Technocore publication: {record['status'].upper()}",
                f"Room: {record['room']}",
                f"Sequence: {record.get('seq') or 'unconfirmed'}",
                f"Nonce: {record['nonce']}",
                f"Timestamp: {record.get('timestamp') or 'unconfirmed'}",
                f"Message: {record['text']}",
            ]
        )

    lines.extend(
        [
            "",
            "This file contains public verification data only.",
            "It does not contain a private key, seed, or password.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_proof_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="watch_room.py --create-proof",
        description=(
            "Create a locally signed contribution proof and human-readable "
            "evidence export."
        ),
    )
    parser.add_argument("repository", help="Public HTTPS Git repository URL")
    parser.add_argument("commit", help="Full 40- or 64-character commit hash")
    parser.add_argument(
        "--identity-dir",
        default=None,
        help=(
            "Folder containing agent_did.txt and agent_private_key.pem. "
            "Defaults to the folder containing this script."
        ),
    )
    parser.add_argument(
        "--output",
        default="contribution-proof.json",
        help="Signed JSON proof path (default: contribution-proof.json)",
    )
    parser.add_argument(
        "--evidence-output",
        default="contribution-evidence.txt",
        help=(
            "Human-readable evidence path "
            "(default: contribution-evidence.txt)"
        ),
    )
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Publish one signed commit-proof message to Technocore",
    )
    parser.add_argument(
        "--room",
        default="technocore",
        help="Technocore proof room used with --publish (default: technocore)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace existing proof and evidence output files",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate inputs without loading a key, writing files, or publishing",
    )
    return parser.parse_args(argv)


def parse_verify_proof_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="watch_room.py --verify-proof",
        description="Verify a V3 contribution proof without a private key.",
    )
    parser.add_argument("proof_file", help="Path to contribution-proof.json")
    parser.add_argument(
        "--evidence-output",
        default=None,
        help="Optionally export a verified human-readable evidence file",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing evidence output file",
    )
    return parser.parse_args(argv)


def create_proof_main(argv=None):
    args = parse_proof_args(argv)

    try:
        repository = normalize_repository_url(args.repository)
        commit = normalize_commit_hash(args.commit)
    except ProofError as error:
        print("ERROR:", error)
        raise SystemExit(2)

    if not ROOM_PATTERN.fullmatch(args.room):
        print("ERROR: Invalid Technocore proof room.")
        raise SystemExit(2)

    script_dir = Path(__file__).resolve().parent
    identity_dir = (
        Path(args.identity_dir).expanduser().resolve()
        if args.identity_dir
        else script_dir
    )
    output_path = Path(args.output).expanduser().resolve()
    evidence_path = Path(args.evidence_output).expanduser().resolve()

    if output_path == evidence_path:
        print("ERROR: Proof and evidence outputs must use different paths.")
        raise SystemExit(2)

    existing_outputs = [
        str(path)
        for path in (output_path, evidence_path)
        if path.exists() and not args.force
    ]

    if existing_outputs:
        print("ERROR: Output file(s) already exist:")
        for path in existing_outputs:
            print(" ", path)
        print("Use --force to replace them.")
        raise SystemExit(2)

    if args.dry_run:
        print("PROOF DRY RUN OK")
        print("Repository:", repository)
        print("Commit:", commit)
        print("Commit URL:", commit_url_for(repository, commit))
        print("Identity directory:", identity_dir)
        print("Publish:", "yes" if args.publish else "no")
        print("No key was loaded.")
        print("No file was written.")
        print("No network request was sent.")
        return

    try:
        did, encrypted_key = load_identity_files(identity_dir)
    except (FileNotFoundError, ProofError) as error:
        print("ERROR:", error)
        raise SystemExit(2)

    password = getpass("Private-key password: ")

    try:
        private_key = unlock_and_verify_identity(
            did,
            encrypted_key,
            password,
        )
    except ProofError as error:
        print("ERROR:", error)
        raise SystemExit(1)
    finally:
        password = None

    document = create_proof_document(did, private_key, repository, commit)
    exit_code = 0

    if args.publish:
        text = proof_message_text(document)
        print("Publishing one signed Technocore proof message...")

        try:
            document["technocore"] = publish_contribution_proof(
                args.room,
                did,
                private_key,
                text,
            )
        except PublishUncertainError as error:
            document["technocore"] = {
                "status": "uncertain",
                "room": error.room,
                "seq": None,
                "nonce": error.nonce,
                "timestamp": None,
                "text": error.text,
            }
            print("WARNING:", error)
            exit_code = 6
        except ProofError as error:
            print("ERROR:", error)
            document["technocore"] = None
            exit_code = 5
    else:
        document["technocore"] = None

    try:
        seal_proof_document(document, private_key)
        verify_proof_document(document)
        validate_technocore_record(document)
        write_output_file(
            output_path,
            json.dumps(document, indent=2, ensure_ascii=False) + "\n",
            args.force,
        )
        write_output_file(
            evidence_path,
            evidence_text(document),
            args.force,
        )
    except ProofError as error:
        print("ERROR:", error)
        raise SystemExit(2)

    print()
    print("SIGNED PROOF CREATED")
    print("DID:", did)
    print("Commit:", commit)
    print("Proof:", output_path)
    print("Evidence:", evidence_path)

    if document["technocore"]:
        record = document["technocore"]
        print("Technocore status:", record["status"])
        print("Room:", record["room"])
        print("Sequence:", record.get("seq") or "unconfirmed")
        print("Nonce:", record["nonce"])

    if exit_code:
        raise SystemExit(exit_code)


def verify_proof_main(argv=None):
    args = parse_verify_proof_args(argv)
    proof_path = Path(args.proof_file).expanduser().resolve()

    try:
        document = json.loads(proof_path.read_text(encoding="utf-8"))
        did = verify_proof_document(document)
        validate_technocore_record(document)

        if args.evidence_output:
            evidence_path = Path(args.evidence_output).expanduser().resolve()
            write_output_file(
                evidence_path,
                evidence_text(document),
                args.force,
            )
            print("Evidence:", evidence_path)
    except (OSError, json.JSONDecodeError, ProofError) as error:
        print("INVALID PROOF:", error)
        raise SystemExit(1)

    print("VALID PROOF")
    print("DID:", did)
    print("Commit:", document["commit"])


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


def watch_main():
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

    if args.dry_run:
        print("DRY RUN OK")
        print("Room:", room)
        print("Room name is valid.")
        print("Identity directory:", identity_dir)
        print("No key was loaded.")
        print("No network request was sent.")
        raise SystemExit(0)

    try:
        did, encrypted_key = load_identity_files(identity_dir)
    except FileNotFoundError as error:
        print("ERROR: Required identity file(s) not found:", error)
        print(
            "Use --identity-dir to point to the folder containing "
            "agent_did.txt and agent_private_key.pem."
        )
        raise SystemExit(2)
    except ProofError as error:
        print("ERROR:", error)
        raise SystemExit(2)

    password = getpass("Private-key password: ")

    try:
        private_key = unlock_and_verify_identity(
            did,
            encrypted_key,
            password,
        )
    except ProofError as error:
        print("ERROR:", error)
        print("No request was sent.")
        exit_code = 1 if str(error).startswith("Wrong password") else 2
        raise SystemExit(exit_code)
    finally:
        password = None

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

            try:
                room_exists = public_room_exists(room)
            except RoomLookupError as error:
                print(
                    "Room status could not be confirmed. "
                    "No signed write will be sent."
                )
                print("Reason:", error)
                print(f"Rechecking in {interval:g}s...")
                time.sleep(interval)
                continue

            if room_exists:
                print("ROOM ALREADY EXISTS")
                print("No signed write was sent.")
                raise SystemExit(3)

            attempt += 1

            now = int(time.time() * 1000)
            nonce_int = max(now, last_nonce + 1)
            last_nonce = nonce_int
            nonce = str(nonce_int)

            url = signed_write_url(
                room,
                did,
                private_key,
                nonce,
                text,
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

            except (urllib.error.URLError, TimeoutError) as error:
                wait_seconds = max(interval, 10.0)

                print(
                    "Network error after sending the request:",
                    getattr(error, "reason", error),
                )
                print("The write result is uncertain. Verifying the room...")

                while True:
                    try:
                        outcome = reconcile_ambiguous_write(
                            room,
                            did,
                            nonce,
                            text,
                        )
                    except RoomLookupError as lookup_error:
                        print(
                            "Could not verify the previous write. "
                            "No additional write will be sent."
                        )
                        print("Reason:", lookup_error)
                        print(f"Rechecking in {wait_seconds:g}s...")
                        time.sleep(wait_seconds)
                        continue

                    if outcome == WRITE_CONFIRMED:
                        print()
                        print("ROOM CREATED SUCCESSFULLY!")
                        print("Confirmed by DID, nonce, and text after timeout.")
                        print("\a")
                        return

                    if outcome == ROOM_OCCUPIED:
                        print()
                        print("ROOM NOW EXISTS")
                        print(
                            "The uncertain write was not found. "
                            "No additional signed write was sent."
                        )
                        raise SystemExit(6)

                    print(
                        "The previous write was not found and the room "
                        "is still empty."
                    )
                    print(f"Retrying in {wait_seconds:g}s...")
                    time.sleep(wait_seconds)
                    break

    except KeyboardInterrupt:
        print()
        print("Watcher stopped by user.")
        raise SystemExit(130)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--create-proof":
        create_proof_main(sys.argv[2:])
        return

    if len(sys.argv) > 1 and sys.argv[1] == "--verify-proof":
        verify_proof_main(sys.argv[2:])
        return

    watch_main()


if __name__ == "__main__":
    main()
