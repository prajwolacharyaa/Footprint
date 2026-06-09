#!/usr/bin/env bash
set -euo pipefail

echo "[+] Installing Footprint dependencies with apt"
sudo apt update
sudo apt install -y python3 python3-requests python3-jinja2 python3-colorama

echo "[+] Optional tools:"
echo "    sudo apt install -y sherlock"
echo "    sudo apt install -y pipx && pipx install holehe"
echo
echo "[+] Run:"
echo "    python3 footprint"
