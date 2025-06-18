#!/bin/bash

# Check Python version
REQUIRED="3.12.0"
CURRENT=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')

if [ "$(printf '%s\n' "$REQUIRED" "$CURRENT" | sort -V | head -n1)" != "$REQUIRED" ]; then
    echo "Python version must be >= 3.12.0 (found $CURRENT)"
    exit 1
fi

# Install requirements
pip3 install -r requirements.txt || exit 1

# Determine install mode
MODE="-e ."
if [ "$1" == "--prod" ]; then
    MODE="."
fi

# Install in order
cd edoi_net || exit 1
pip3 install $MODE || exit 1
cd ..

cd httpe_core || exit 1
pip3 install $MODE || exit 1
cd ..

cd httpe_client || exit 1
pip3 install $MODE || exit 1
cd ..

cd httpe_server || exit 1
pip3 install $MODE || exit 1
cd ..

echo "Setup complete."
