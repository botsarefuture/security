#!/bin/bash

# Set the installation directory
INSTALL_DIR="/opt/security"

# Clone the GitHub repository
git clone https://github.com/botsarefuture/security.git "$INSTALL_DIR"

# Change to the installation directory
cd "$INSTALL_DIR"

# Install dependencies
pip install -r requirements.txt

# Create a virtual environment (optional)
# python -m venv venv
# source venv/bin/activate

# Start the application
python app.py
