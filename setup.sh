#!/bin/bash

echo "Setting up GraphQL MCP Server..."

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "Creating .env file from .env.example..."
    cp .env.example .env
    echo "⚠️  Please edit .env file with your GraphQL endpoint and credentials"
else
    echo "✓ .env file already exists"
fi

echo ""
echo "Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit .env file with your GraphQL endpoint"
echo "2. Run the server:"
echo "   - Stdio mode: python server.py"
echo "   - HTTP/SSE mode: python server_http.py"
echo ""
