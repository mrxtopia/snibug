#!/usr/bin/env bash
# Run THIS file on Android Termux if bash termux_setup.sh shows $'\r' errors.
# It removes Windows carriage returns then runs the real installer.
cd "$(dirname "$0")" || exit 1
test -f termux_setup.sh || { echo "termux_setup.sh not found in $(pwd)"; exit 1; }
tr -d '\r' < termux_setup.sh | bash -s "$@"
