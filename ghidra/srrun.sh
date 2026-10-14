#!/bin/bash
# headless Ghidra on the SegaRally project. usage: srrun.sh <log> [headless args after project name]
# Set GHIDRA_HEADLESS (path to analyzeHeadless) and SR_GHIDRA (folder holding SegaRally.gpr); scripts in ./scripts.
log="$1"; shift
"$GHIDRA_HEADLESS" "$SR_GHIDRA" SegaRally "$@" -scriptPath "$(dirname "$0")/scripts" > "$log" 2>&1
tail -3 "$log"
