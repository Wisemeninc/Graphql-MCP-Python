"""
Simple test to verify the GraphQL MCP server setup
"""

import sys
import os

def check_environment():
    """Check if environment is properly configured"""
    print("Checking environment configuration...")
    
    required_vars = ["GRAPHQL_ENDPOINT"]
    missing = []
    
    for var in required_vars:
        value = os.getenv(var)
        if not value:
            missing.append(var)
            print(f"  ❌ {var}: Not set")
        else:
            # Hide sensitive values
            display_value = value if len(value) < 50 else value[:20] + "..."
            print(f"  ✓ {var}: {display_value}")
    
    optional_vars = ["GRAPHQL_AUTH_TOKEN", "GRAPHQL_HEADERS", "MCP_HOST", "MCP_PORT"]
    for var in optional_vars:
        value = os.getenv(var)
        if value:
            display_value = "***" if "TOKEN" in var else (value if len(value) < 50 else value[:20] + "...")
            print(f"  ✓ {var}: {display_value}")
    
    if missing:
        print(f"\n⚠️  Missing required environment variables: {', '.join(missing)}")
        print("Please set them in your .env file")
        return False
    
    print("\n✓ Environment configuration looks good!")
    return True


def check_imports():
    """Check if required packages are installed"""
    print("\nChecking required packages...")
    
    packages = [
        ("mcp", "MCP SDK"),
        ("gql", "GraphQL Client"),
        ("graphql", "GraphQL Core"),
        ("aiohttp", "Async HTTP Client"),
        ("starlette", "Web Framework"),
        ("sse_starlette", "SSE Support"),
        ("dotenv", "Environment Variables"),
        ("pydantic", "Data Validation"),
        ("uvicorn", "ASGI Server")
    ]
    
    all_installed = True
    for module_name, display_name in packages:
        try:
            __import__(module_name)
            print(f"  ✓ {display_name}")
        except ImportError:
            print(f"  ❌ {display_name} - Not installed")
            all_installed = False
    
    if not all_installed:
        print("\n⚠️  Some packages are missing. Run: pip install -r requirements.txt")
        return False
    
    print("\n✓ All required packages are installed!")
    return True


def check_files():
    """Check if required files exist"""
    print("\nChecking required files...")
    
    files = [
        ("server.py", "Main server (stdio)"),
        ("server_mcp_http_stateful.py", "HTTP/SSE server"),
        ("requirements.txt", "Dependencies"),
        (".env.example", "Environment template"),
    ]
    
    all_exist = True
    for filename, description in files:
        filepath = os.path.join(os.path.dirname(__file__), filename)
        if os.path.exists(filepath):
            print(f"  ✓ {filename} - {description}")
        else:
            print(f"  ❌ {filename} - Missing")
            all_exist = False
    
    env_file = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_file):
        print(f"  ✓ .env - Configuration file")
    else:
        print(f"  ⚠️  .env - Not found (copy from .env.example)")
    
    if not all_exist:
        return False
    
    print("\n✓ All required files are present!")
    return True


def main():
    """Run all checks"""
    print("=" * 60)
    print("GraphQL MCP Server - Setup Verification")
    print("=" * 60)
    
    from dotenv import load_dotenv
    load_dotenv()
    
    checks = [
        check_files(),
        check_imports(),
        check_environment()
    ]
    
    print("\n" + "=" * 60)
    if all(checks):
        print("✓ Setup verification complete! Everything looks good.")
        print("\nYou can now start the server:")
        print("  - Stdio mode: python server.py")
        print("  - HTTP/SSE mode: python server_mcp_http_stateful.py")
    else:
        print("⚠️  Setup incomplete. Please address the issues above.")
        sys.exit(1)
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except ImportError as e:
        print(f"\n❌ Import error: {e}")
        print("Please run: pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
