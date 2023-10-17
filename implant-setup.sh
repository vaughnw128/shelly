#!/bin/bash

echo "Installing Requirements..."
pip install -r requirements.txt

pyinstaller --onefile -y ./src/implant.py