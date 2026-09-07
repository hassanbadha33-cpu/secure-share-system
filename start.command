#!/bin/bash
# ============================================================================
#  Secure Share System — Easy Launcher (macOS)
#  Just double-click this file (or run:  ./start.command)
#
#  It starts the server and opens the website in your browser.
#  If the server is already running, it simply opens the browser.
#  Close the Terminal window (or press Ctrl+C) to stop the server.
# ============================================================================

cd "$(dirname "$0")"

# Make sure Node.js is available (Homebrew installs it to /opt/homebrew/bin)
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

if ! command -v node >/dev/null 2>&1; then
  echo ""
  echo "[!] Node.js was not found on this computer."
  echo "    Install it from https://nodejs.org (LTS version), then run this file again."
  echo ""
  read -r -p "Press Enter to close..."
  exit 1
fi

# Node 22.5+ is required (uses the built-in SQLite module)
NODE_MAJOR=$(node -e "console.log(process.versions.node.split('.')[0])")
if [ "${NODE_MAJOR:-0}" -lt 22 ]; then
  echo ""
  echo "[!] Node.js version 22 or newer is required."
  echo "    You have version $NODE_MAJOR.x - update it from https://nodejs.org"
  echo ""
  read -r -p "Press Enter to close..."
  exit 1
fi

URL="http://127.0.0.1:3000"

# Already running? Just open the browser.
if curl -s -o /dev/null --max-time 2 "$URL/login.html" 2>/dev/null; then
  echo ""
  echo "The Secure Share System is already running."
  echo "Opening $URL ..."
  open "$URL"
  echo ""
  read -r -p "Press Enter to close..."
  exit 0
fi

echo ""
echo "============================================================"
echo "  Starting Secure Share System ..."
echo "  Demo logins:  admin / Admin@123   manager / Manager@123"
echo "                employee / Employee@123"
echo "  Press Ctrl+C (or close this window) to stop the server."
echo "============================================================"
echo ""

# Start the server in the background, then open the browser once it is ready.
node server.js &
SERVER_PID=$!

for i in $(seq 1 20); do
  if curl -s -o /dev/null --max-time 1 "$URL/login.html" 2>/dev/null; then
    break
  fi
  sleep 1
done

open "$URL"
wait $SERVER_PID
