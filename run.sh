#!/bin/bash

# GraphQL MCP Server Runner Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run ./setup.sh first"
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "❌ .env file not found. Please create it from .env.example"
    exit 1
fi

# Parse command line arguments
MODE=${1:-http}

case $MODE in
    stdio)
        echo "Starting GraphQL MCP Server in stdio mode..."
        python server.py
        ;;
    http|sse)
        echo "Starting GraphQL MCP Server in HTTP/SSE mode..."
        python server_http.py
        ;;
    test)
        echo "Running setup verification..."
        python test_setup.py
        ;;
    *)
        echo "Usage: $0 [stdio|http|test]"
        echo ""
        echo "Modes:"
        echo "  stdio - Run with stdio transport (for local MCP clients)"
        echo "  http  - Run with HTTP/SSE transport (default)"
        echo "  test  - Verify setup and configuration"
        exit 1
        ;;
esac
