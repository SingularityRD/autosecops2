# shellcheck shell=bash
# shellcheck disable=SC1091
# Test/gates environment for AutoSecOps work packages.
# Usage: GATES_ENV_SH=docs/wp/briefs/gates_env.sh scripts/wp/gates.sh --base integration
# Loads the main checkout's venv and .env (set AUTOSECOPS_MAIN to override), then
# neutralises settings that make unit tests environment-dependent.
_main="${AUTOSECOPS_MAIN:-/root/vigil}"
if [ -f "$_main/venv/bin/activate" ]; then . "$_main/venv/bin/activate"; fi
if [ -f "$_main/.env" ]; then set -a; . "$_main/.env"; set +a; fi
: "${JWT_SECRET_KEY:=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')}"
export JWT_SECRET_KEY
unset DAEMON_AUTO_TRIAGE
export DEMO_MODE=false MCP_AUTO_CONNECT_ON_STARTUP=false
