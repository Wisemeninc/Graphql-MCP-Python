# Scripts and Utilities

Helper scripts for setup, testing, and examples.

## Setup Scripts

### setup.sh
Automated environment setup script that:
- Creates Python virtual environment
- Installs dependencies from requirements.txt
- Copies .env.example to .env
- Validates configuration

**Usage:**
```bash
./scripts/setup.sh
```

### run.sh
Convenience runner script that:
- Activates virtual environment
- Starts the MCP server with the specified transport

**Usage:**
```bash
# Run stdio transport (for Claude Desktop)
./scripts/run.sh

# Run HTTP/SSE transport
./scripts/run.sh http
```

## Testing

### test_setup.py
Setup verification tool that validates:
- Python environment is configured correctly
- All required packages are installed
- Environment variables are set
- GraphQL endpoint is accessible

**Usage:**
```bash
python scripts/test_setup.py
```

## Examples

### example_client.py
Example MCP client demonstrating:
- How to connect to the MCP server
- Tool execution patterns
- Query and mutation examples
- Error handling

**Usage:**
```bash
# Make sure the MCP server is running first
python server_mcp_http_stateful.py

# In another terminal
python scripts/example_client.py
```

## Quick Start

For new installations:

1. Run setup: `./scripts/setup.sh`
2. Configure environment: Edit `.env` file
3. Validate setup: `python scripts/test_setup.py`
4. Start server: `./scripts/run.sh` or `docker-compose up`
