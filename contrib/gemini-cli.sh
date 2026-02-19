#!/bin/sh
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
source ~/.bashrc

# Install latest LTS Node.js
nvm install --lts
nvm use --lts

# Verify installation
node --version
npm --version

# Install gemini-cli latest
npm install -g @google/gemini-cli

# Check version
gemini --version
which gemini
