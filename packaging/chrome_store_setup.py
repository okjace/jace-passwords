#!/usr/bin/env python3
"""Run once:  python3 packaging/chrome_store_setup.py

Saves what CI needs to upload every release to the Chrome Web Store, as GitHub secrets, without printing them:
  - the Google Cloud service account's JSON key file (you download it; this reads it)
  - your Chrome Web Store publisher ID
  - the extension's item ID (already filled in)
After that, every release is uploaded and submitted for review by itself (packaging/publish_chrome.py).
"""
import json
import subprocess
import sys
from pathlib import Path

REPO = "okjace/jace-passwords"
ITEM_ID = "lnbpganekbjbcjbchggdbieaballolcl"


def secret(name: str, value: str) -> None:
    subprocess.run(["gh", "secret", "set", name, "-R", REPO], input=value.encode(), check=True, capture_output=True)


def main() -> int:
    print("Chrome Web Store automatic uploads\n")
    path = Path(input("Path to the service account's JSON key file (drag it into this window): ").strip().strip("'\"")).expanduser()
    try:
        key = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        print(f"Couldn't read that file: {e}", file=sys.stderr)
        return 1
    if key.get("type") != "service_account" or not key.get("private_key") or not key.get("client_email"):
        print("That isn't a service account key (it needs type service_account, client_email and private_key).", file=sys.stderr)
        return 1
    publisher = input("Publisher ID (Chrome Web Store Developer Dashboard → Publisher → Settings): ").strip()
    if not publisher:
        print("The publisher ID is needed.", file=sys.stderr)
        return 1
    secret("CWS_SERVICE_ACCOUNT", json.dumps(key))
    secret("CWS_PUBLISHER_ID", publisher)
    secret("CWS_EXTENSION_ID", ITEM_ID)
    print(f"\nSaved. The service account is {key['client_email']}:")
    print("make sure it's added in the Developer Dashboard → Account → Service account.")
    print("You can delete the JSON key file from this computer now; GitHub has it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
