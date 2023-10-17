#!/bin/bash

echo "Installing Requirements..."
pip install -r ./src/requirements.txt

pyinstaller --onefile -y ./src/implant.py

