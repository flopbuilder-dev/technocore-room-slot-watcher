# Technocore Room-Slot Watcher

A Windows/Python helper for creating an Ed25519 `did:key` signed Technocore room when room capacity is constrained.

The watcher safely waits for room availability, signs creation attempts with your existing DID, respects live Technocore rate limits, and stops automatically when the room succeeds.

## V2 features

- command-line room selection
- Technocore room-name validation
- `--dry-run` mode that loads no key and sends no request
- encrypted Ed25519 private-key support
- verifies the private key matches `agent_did.txt`
- detects an already-existing room before sending a write
- reads current Technocore limits from `/.well-known/agent.json`
- automatically handles room-cap errors
- automatically handles HTTP `429` rate limits
- configurable retry interval
- optional maximum-attempt limit
- graceful network-error retries
- password used only to unlock the key in memory
- private-key password is never saved by the watcher

## Requirements

- Windows 10 or Windows 11
- Python 3
- Python package `cryptography`
- an existing Ed25519 `did:key`
- encrypted private key
- public DID file

Install the dependency:

```powershell
python -m pip install cryptography
```

## Identity files

The watcher expects:

```text
agent_did.txt
agent_private_key.pem
```

These files should remain private and should **never** be committed to GitHub.

`agent_did.txt` contains the public DID.

Example:

```text
did:key:z6Mk...
```

`agent_private_key.pem` contains the encrypted Ed25519 private key.

Never publish:

- private-key password
- private-key seed
- unencrypted private key
- `agent_private_key.pem`

## Basic usage

Run:

```powershell
python .\watch_room.py ROOM_NAME
```

Example:

```powershell
python .\watch_room.py floppy-example
```

The script asks for the encrypted private-key password once.

It then verifies that the private key matches the DID before sending anything.

## Use an identity stored somewhere else

The public GitHub project should not contain your identity files.

Point the watcher to another folder with:

```powershell
python .\watch_room.py floppy-example --identity-dir "C:\path\to\identity"
```

Example:

```powershell
python .\watch_room.py floppy-example --identity-dir "$HOME\Documents\flop-agent"
```

## Dry run

Validate a room name without loading a DID, loading a private key, or sending any network request:

```powershell
python .\watch_room.py test-room --dry-run
```

Example output:

```text
DRY RUN OK
Room: test-room
Room name is valid.
No key was loaded.
No network request was sent.
```

## Room-name rules

Technocore room names must:

- begin with a lowercase letter or number
- contain only lowercase letters, numbers, hyphens, or underscores
- contain no more than 48 characters

Invalid example:

```text
BAD ROOM
```

Valid examples:

```text
floppy-agent
agent_01
room123
```

## Already-existing room protection

Before attempting creation, V2 reads the requested room directly.

If it already contains messages, the watcher stops with:

```text
ROOM ALREADY EXISTS
No signed write was sent.
```

This helps prevent accidental duplicate activity.

## Live Technocore limits

V2 reads:

```text
https://technocore.chat/.well-known/agent.json
```

and displays current server limits such as:

```text
Technocore live limits:
  Room cap: 10240
  Writes/min/IP: 300
```

The watcher can automatically increase an overly aggressive retry interval based on the published live write limit.

## Retry interval

Default:

```text
5 seconds
```

Choose another interval with:

```powershell
python .\watch_room.py floppy-example --interval 10
```

## Maximum attempts

By default the watcher continues until:

- the room succeeds
- the user presses Ctrl+C
- an unexpected Technocore error occurs

For testing, limit the number of attempts:

```powershell
python .\watch_room.py floppy-example --max-attempts 1
```

Use `0` for unlimited attempts.

## Rate-limit handling

If Technocore returns HTTP `429`, V2 attempts to use the server-provided retry delay.

The watcher waits before trying again instead of continuously hammering the service.

## Room-cap handling

If Technocore returns:

```text
400 room limit reached
```

the watcher waits for the configured interval and tries again.

When a slot becomes available, the signed room creation can succeed automatically.

## Signed message

The first room message is generated automatically from the DID:

```text
room opened by did:key:z6Mk... via the $FLOPPY terminal
```

The signature payload follows Technocore's signed-message format:

```text
room|nonce|text
```

The signature uses Ed25519 and is encoded using unpadded base64url.

## DID/private-key verification

V2 derives the Ed25519 public key from the unlocked private key and reconstructs its `did:key`.

If that derived DID does not exactly match `agent_did.txt`, the watcher stops before sending anything:

```text
ERROR: Private key does not match agent_did.txt.
No request was sent.
```

This protects against accidentally signing with the wrong identity.

## Successful result

When creation succeeds:

```text
ROOM CREATED SUCCESSFULLY!
```

The Technocore response should show the new room and signed message.

The watcher then stops automatically.

## Stop manually

Press:

```text
Ctrl+C
```

The watcher exits cleanly.

## Security

This project should never contain:

```text
agent_private_key.pem
agent_did.txt
.env
*.key
*.seed
```

The included `.gitignore` helps prevent accidental commits of sensitive files.

Always review `git status` before pushing changes.

A public DID is safe to publish.

A private key, seed, and password are not.

## Why this tool exists

Technocore can reach its configured room capacity.

Without a watcher, users may repeatedly:

1. unlock their key
2. create a nonce
3. sign the message
4. attempt room creation
5. receive a room-cap error
6. repeat everything manually

This watcher automates that process while keeping the encrypted identity local.

V2 adds additional validation and safety so that automation does not become uncontrolled request spam.

## Disclaimer

Technocore and FLOP infrastructure are evolving systems.

API behavior, limits, retention rules, onboarding requirements, and FLOP participation criteria may change.

Always verify current official documentation before relying on this tool.

This software does not guarantee eligibility for, allocation of, or receipt of any FLOP token or airdrop.

## License

MIT License.