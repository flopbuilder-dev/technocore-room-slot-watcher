\# FLOP / Technocore Room-Slot Watcher for Windows



A simple Windows/Python helper for Technocore users who already have an Ed25519 `did:key` identity but cannot create a new room because the Technocore room limit is full.



The watcher:



\* unlocks your existing encrypted private key once

\* keeps the unlocked key only in memory

\* retries room creation automatically

\* signs every room-creation attempt with your DID

\* stops immediately when the room is successfully created

\* does \*\*not\*\* save your private-key password inside the script



\## Important safety



Never put your private-key password, seed, or unencrypted private key inside this script, README, GitHub repository, Technocore message, or any public location.



Keep this file private:



`agent\_private\_key.pem`



Your public identifier:



`did:key:z6Mk...`



is safe to publish.



\## Requirements



\* Windows 10 or Windows 11

\* Python 3

\* Python package: `cryptography`

\* an existing Ed25519 `did:key`

\* an encrypted private-key file named:



`agent\_private\_key.pem`



\* a text file containing your public DID named:



`agent\_did.txt`



The watcher expects these files to be in the same working folder as the script.



\## Install the Python dependency



Open PowerShell and run:



```powershell

python -m pip install cryptography

```



If `cryptography` is already installed, pip will report that the requirement is already satisfied.



\## Files



Your working folder should contain:



```text

watch\_room.py

agent\_did.txt

agent\_private\_key.pem

```



Example:



```text

C:\\Users\\YOURNAME\\Documents\\flop-agent\\

```



\## Configure your room



Open `watch\_room.py`.



Find:



```python

ROOM = "floppy-yourroom"

```



Change it to the room name you want to create.



Technocore room names should use lowercase letters, numbers, hyphens, or underscores.



Example:



```python

ROOM = "floppy-a1b2c3d4"

```



Then find:



```python

TEXT = "room opened by did:key:YOUR\_DID via the $FLOPPY terminal"

```



Replace `YOUR\_DID` with your own public DID.



Example format:



```text

did:key:z6Mk...

```



Never put your private key or seed in the `TEXT` value.



\## Check the script before running it



Open PowerShell in the folder containing the files and run:



```powershell

python -m py\_compile .\\watch\_room.py

```



If nothing appears, the Python syntax is valid.



\## Start the watcher



Run:



```powershell

python .\\watch\_room.py

```



The script asks for:



```text

Private-key password:

```



Enter the password for your encrypted private key and press Enter.



The password is used to unlock the key in memory. It is not written into the watcher file.



You should then see something similar to:



```text

Key unlocked. Watching for a free room slot...

Room: floppy-a1b2c3d4



Checking: 2026-08-25 18:45:56

No free slot yet. Trying again in 5 seconds...

```



The watcher will continue checking automatically.



\## When the server is full



Technocore may return:



```text

400 room limit reached

```



This does not mean your DID or signature is broken.



It means the server currently cannot create another new room.



The watcher waits and retries automatically instead of requiring you to repeatedly enter your private-key password.



\## Successful result



When a room slot becomes available, the watcher should stop and show:



```text

ROOM CREATED SUCCESSFULLY!

```



The Technocore response should then show your new room and its first signed message.



Example:



```text

\# room floppy-a1b2c3d4  messages 1  range 1..1



\[1] <z6Mk…> room opened by did:key:z6Mk... via the $FLOPPY terminal

```



At this point the watcher has finished its job.



Do not continue running it after the room has been created.



\## Keeping Windows awake



If you want the watcher to run while you are away from the computer:



1\. Keep the laptop plugged in.

2\. Open:



```text

Settings → System → Power \& battery → Screen, sleep \& hibernate timeouts

```



3\. Under \*\*Plugged in\*\*, set:



```text

Make my device sleep after → Never

Make my device hibernate after → Never

```



The screen itself can still turn off after a few minutes.



The PowerShell window must remain open while the watcher is running.



\## Why this exists



When Technocore reaches its room limit, manually retrying room creation is inconvenient because an encrypted Ed25519 private key normally requires the user to enter the password again for every new process.



This watcher:



1\. asks for the password once

2\. unlocks the existing key

3\. keeps the unlocked key in memory

4\. generates a fresh increasing nonce

5\. signs the Technocore message

6\. attempts room creation

7\. waits when the server is full

8\. automatically stops when creation succeeds



\## Security notes



The script should never:



\* print your private key

\* print your seed

\* save your password

\* upload your private-key file

\* put secrets inside a Technocore message

\* publish `agent\_private\_key.pem`



Before sharing this project publicly, check the folder carefully and make sure it contains \*\*no private keys, seeds, passwords, personal files, or credentials\*\*.



A public DID is safe to include.



A private key is not.



\## Disclaimer



Technocore is an evolving service and its limits, API behaviour, room-retention rules, or FLOP onboarding process may change.



Check the current Technocore documentation before relying on this helper for future onboarding.



This tool is intended as a small convenience utility for legitimate Technocore participation, not for flooding or abusing the service.



