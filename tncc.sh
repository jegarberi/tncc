#!/bin/bash
# Wrapper script for TNCC binary
# Passes all arguments to the tncc binary

# Determine script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Execute tncc binary with all arguments
exec "${SCRIPT_DIR}/tncc" "$@"
