#!/usr/bin/env bash
# Start Jace Passwords (opens it in your browser). Needs Python 3.10+ and the "cryptography" package.
cd "$(dirname "$0")"
python3 -c "import cryptography" 2>/dev/null || python3 -m pip install --user -r requirements.txt
exec python3 -m jace_passwords "$@"
