#!/bin/bash

echo "Installing Requirements..."
pip install -r ./requirements.txt

pyinstaller --one-file -y ./src/implant.py