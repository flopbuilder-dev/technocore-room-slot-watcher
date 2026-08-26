import argparse
import io
import json
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import watch_room
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class FakeResponse:
    def __init__(self, data):
        self.payload = json.dumps(data).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self):
        return self.payload


class RoomSafetyTests(unittest.TestCase):
    def make_identity(self, directory):
        password = b"test-password"
        private_key = Ed25519PrivateKey.generate()
        did = watch_room.did_from_private_key(private_key)
        encrypted_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )

        Path(directory, "agent_did.txt").write_text(did, encoding="utf-8")
        Path(directory, "agent_private_key.pem").write_bytes(encrypted_key)
        return password.decode("ascii")

    def make_args(self, identity_dir):
        return argparse.Namespace(
            room="test-room",
            identity_dir=identity_dir,
            interval=1.0,
            max_attempts=2,
            dry_run=False,
        )

    def test_existing_room_is_detected(self):
        response = FakeResponse({"last_seq": 12, "messages": []})

        with patch("watch_room.urllib.request.urlopen", return_value=response):
            self.assertTrue(watch_room.public_room_exists("existing-room"))

    def test_empty_room_is_not_reported_as_existing(self):
        response = FakeResponse({"last_seq": 0, "messages": []})

        with patch("watch_room.urllib.request.urlopen", return_value=response):
            self.assertFalse(watch_room.public_room_exists("empty-room"))

    def test_room_lookup_failure_is_not_treated_as_absence(self):
        error = urllib.error.URLError("temporary network failure")

        with patch("watch_room.urllib.request.urlopen", side_effect=error):
            with self.assertRaises(watch_room.RoomLookupError):
                watch_room.public_room_exists("unknown-room")

    def test_invalid_room_response_fails_closed(self):
        response = FakeResponse(["unexpected", "response"])

        with patch("watch_room.urllib.request.urlopen", return_value=response):
            with self.assertRaises(watch_room.RoomLookupError):
                watch_room.public_room_exists("unknown-room")

    def test_ambiguous_write_is_confirmed_by_exact_identity_fields(self):
        response = FakeResponse(
            {
                "last_seq": 41,
                "messages": [
                    {
                        "from": "did:key:z6Mktest",
                        "nonce": 123456,
                        "text": "room opened",
                    }
                ],
            }
        )

        with patch("watch_room.urllib.request.urlopen", return_value=response):
            outcome = watch_room.reconcile_ambiguous_write(
                "test-room",
                "did:key:z6Mktest",
                "123456",
                "room opened",
            )

        self.assertEqual(outcome, watch_room.WRITE_CONFIRMED)

    def test_ambiguous_write_stops_when_another_message_occupies_room(self):
        response = FakeResponse(
            {
                "last_seq": 42,
                "messages": [
                    {
                        "from": "did:key:z6Mkother",
                        "nonce": 999,
                        "text": "different message",
                    }
                ],
            }
        )

        with patch("watch_room.urllib.request.urlopen", return_value=response):
            outcome = watch_room.reconcile_ambiguous_write(
                "test-room",
                "did:key:z6Mktest",
                "123456",
                "room opened",
            )

        self.assertEqual(outcome, watch_room.ROOM_OCCUPIED)

    def test_ambiguous_write_can_retry_only_after_confirmed_absence(self):
        response = FakeResponse({"last_seq": 0, "messages": []})

        with patch("watch_room.urllib.request.urlopen", return_value=response):
            outcome = watch_room.reconcile_ambiguous_write(
                "test-room",
                "did:key:z6Mktest",
                "123456",
                "room opened",
            )

        self.assertEqual(outcome, watch_room.WRITE_ABSENT)

    def test_room_is_rechecked_after_capacity_error(self):
        with tempfile.TemporaryDirectory() as identity_dir:
            password = self.make_identity(identity_dir)
            room_cap_error = urllib.error.HTTPError(
                url="https://technocore.chat",
                code=400,
                msg="room limit reached",
                hdrs={},
                fp=io.BytesIO(b"room limit reached"),
            )
            self.addCleanup(room_cap_error.close)

            with (
                patch("watch_room.parse_args", return_value=self.make_args(identity_dir)),
                patch("watch_room.getpass", return_value=password),
                patch("watch_room.fetch_live_limits", return_value={}),
                patch("watch_room.public_room_exists", side_effect=[False, True]) as check,
                patch("watch_room.urllib.request.urlopen", side_effect=room_cap_error) as write,
                patch("watch_room.time.sleep"),
                self.assertRaises(SystemExit) as stopped,
            ):
                with redirect_stdout(io.StringIO()):
                    watch_room.main()

        self.assertEqual(stopped.exception.code, 3)
        self.assertEqual(check.call_count, 2)
        self.assertEqual(write.call_count, 1)

    def test_failed_room_check_sends_no_write(self):
        with tempfile.TemporaryDirectory() as identity_dir:
            password = self.make_identity(identity_dir)

            with (
                patch("watch_room.parse_args", return_value=self.make_args(identity_dir)),
                patch("watch_room.getpass", return_value=password),
                patch("watch_room.fetch_live_limits", return_value={}),
                patch(
                    "watch_room.public_room_exists",
                    side_effect=[watch_room.RoomLookupError("offline"), True],
                ),
                patch("watch_room.urllib.request.urlopen") as write,
                patch("watch_room.time.sleep"),
                self.assertRaises(SystemExit) as stopped,
            ):
                with redirect_stdout(io.StringIO()):
                    watch_room.main()

        self.assertEqual(stopped.exception.code, 3)
        write.assert_not_called()

    def test_timeout_is_reconciled_before_any_resend(self):
        with tempfile.TemporaryDirectory() as identity_dir:
            password = self.make_identity(identity_dir)

            with (
                patch("watch_room.parse_args", return_value=self.make_args(identity_dir)),
                patch("watch_room.getpass", return_value=password),
                patch("watch_room.fetch_live_limits", return_value={}),
                patch("watch_room.public_room_exists", return_value=False),
                patch(
                    "watch_room.urllib.request.urlopen",
                    side_effect=urllib.error.URLError("response lost"),
                ) as write,
                patch(
                    "watch_room.reconcile_ambiguous_write",
                    side_effect=[
                        watch_room.RoomLookupError("read unavailable"),
                        watch_room.WRITE_CONFIRMED,
                    ],
                ) as reconcile,
                patch("watch_room.time.sleep"),
            ):
                with redirect_stdout(io.StringIO()):
                    watch_room.main()

        self.assertEqual(write.call_count, 1)
        self.assertEqual(reconcile.call_count, 2)


class RetryDelayTests(unittest.TestCase):
    def test_retry_after_header_is_used(self):
        error = urllib.error.HTTPError(
            url="https://technocore.chat",
            code=429,
            msg="rate limited",
            hdrs={"Retry-After": "7"},
            fp=None,
        )
        self.addCleanup(error.close)

        self.assertEqual(watch_room.retry_after_seconds(error, ""), 7.0)

    def test_retry_delay_can_be_read_from_body(self):
        error = urllib.error.HTTPError(
            url="https://technocore.chat",
            code=429,
            msg="rate limited",
            hdrs={},
            fp=None,
        )
        self.addCleanup(error.close)

        self.assertEqual(
            watch_room.retry_after_seconds(error, "Please retry after 12 seconds"),
            12.0,
        )


if __name__ == "__main__":
    unittest.main()
