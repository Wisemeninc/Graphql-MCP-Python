#!/usr/bin/env python3
"""
Security Fixes Validation Script

Validates that all critical security fixes have been properly applied.
Run this before deployment to ensure security measures are in place.
"""

import os
import sys

def check_file_exists(filepath, description):
    """Check if a required file exists"""
    if os.path.exists(filepath):
        print(f"✅ {description}: {filepath}")
        return True
    else:
        print(f"❌ {description} NOT FOUND: {filepath}")
        return False

def check_file_contains(filepath, search_strings, description):
    """Check if file contains required strings"""
    if not os.path.exists(filepath):
        print(f"❌ {description}: File not found - {filepath}")
        return False
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    missing = []
    for search_str in search_strings:
        if search_str not in content:
            missing.append(search_str)
    
    if not missing:
        print(f"✅ {description}")
        return True
    else:
        print(f"❌ {description}: Missing implementations")
        for item in missing:
            print(f"   - Missing: {item[:60]}...")
        return False

def main():
    print("=" * 70)
    print("Security Fixes Validation Report")
    print("=" * 70)
    print()
    
    all_passed = True
    
    # Check 1: Rate Limiting
    print("1. Rate Limiting Implementation")
    print("-" * 70)
    passed = check_file_contains(
        'requirements.txt',
        ['slowapi>=0.1.9'],
        "slowapi dependency in requirements.txt"
    )
    all_passed = all_passed and passed
    
    passed = check_file_contains(
        'server_mcp_http_stateful.py',
        [
            'from slowapi import Limiter',
            'limiter = Limiter(key_func=get_remote_address)',
            'await limiter.check_request_limit',
            'app.state.limiter = limiter'
        ],
        "Rate limiting code in server"
    )
    all_passed = all_passed and passed
    print()
    
    # Check 2: CORS Restriction
    print("2. CORS Origin Restriction")
    print("-" * 70)
    passed = check_file_contains(
        'server_mcp_http_stateful.py',
        [
            'ALLOWED_ORIGINS',
            'allowed_origins_str = os.getenv("ALLOWED_ORIGINS"',
            'if ENVIRONMENT == "production"'
        ],
        "CORS restriction implementation"
    )
    all_passed = all_passed and passed
    
    passed = check_file_contains(
        '.env.example',
        ['ALLOWED_ORIGINS='],
        "ALLOWED_ORIGINS in .env.example"
    )
    all_passed = all_passed and passed
    print()
    
    # Check 3: Query Validation
    print("3. GraphQL Query Validation")
    print("-" * 70)
    passed = check_file_contains(
        'server_mcp_http_stateful.py',
        [
            'MAX_QUERY_LENGTH',
            'MAX_QUERY_DEPTH',
            'def validate_graphql_query',
            'validate_graphql_query(query_str)',
            'validate_graphql_query(mutation_str)'
        ],
        "Query validation implementation"
    )
    all_passed = all_passed and passed
    
    passed = check_file_contains(
        '.env.example',
        [
            'MAX_QUERY_LENGTH=',
            'MAX_QUERY_DEPTH=',
        ],
        "Query limits in .env.example"
    )
    all_passed = all_passed and passed
    print()
    
    # Check 4: SSL Verification Enforcement
    print("4. SSL Verification Enforcement")
    print("-" * 70)
    passed = check_file_contains(
        'server_mcp_http_stateful.py',
        [
            'ENVIRONMENT = os.getenv("ENVIRONMENT"',
            'if not SSL_VERIFY and ENVIRONMENT == "production"',
            'CRITICAL SECURITY ERROR'
        ],
        "SSL verification enforcement"
    )
    all_passed = all_passed and passed
    
    passed = check_file_contains(
        '.env.example',
        ['ENVIRONMENT=production'],
        "ENVIRONMENT variable in .env.example"
    )
    all_passed = all_passed and passed
    print()
    
    # Check 5: Input Validation
    print("5. Input Validation")
    print("-" * 70)
    passed = check_file_contains(
        'server_mcp_http_stateful.py',
        [
            'def validate_string_input',
            'def validate_json_input',
            'validate_json_input(variables'
        ],
        "Input validation functions"
    )
    all_passed = all_passed and passed
    print()
    
    # Check 6: Documentation
    print("6. Documentation")
    print("-" * 70)
    passed = check_file_exists(
        'SECURITY_FIXES_APPLIED.md',
        "Security fixes documentation"
    )
    all_passed = all_passed and passed
    print()
    
    # Summary
    print("=" * 70)
    if all_passed:
        print("✅ ALL SECURITY FIXES VALIDATED SUCCESSFULLY")
        print()
        print("Next steps:")
        print("1. Review .env.example and create your .env file")
        print("2. Set ENVIRONMENT=production (or development)")
        print("3. Configure ALLOWED_ORIGINS with your actual domains")
        print("4. Test rate limiting in development")
        print("5. Deploy with confidence!")
        return 0
    else:
        print("❌ VALIDATION FAILED - Some security fixes are missing")
        print()
        print("Please review the failures above and re-apply fixes.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
