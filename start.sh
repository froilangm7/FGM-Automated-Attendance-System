#!/usr/bin/env sh
# Start the attendance server on this phone only (127.0.0.1).
cd "$(dirname "$0")" || exit 1
export TZ="${TZ:-Asia/Manila}"     # attendance times follow this timezone
exec python app.py "$@"
