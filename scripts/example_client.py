"""
Example client script demonstrating GraphQL MCP Server usage
"""

import asyncio
import json
import os
from dotenv import load_dotenv

load_dotenv()

# Example 1: Using with HTTP client
async def example_http_client():
    """Example using HTTP transport"""
    import aiohttp
    
    base_url = "http://localhost:8000"
    
    async with aiohttp.ClientSession() as session:
        # List available tools
        print("=== Listing Tools ===")
        async with session.get(f"{base_url}/tools") as resp:
            tools = await resp.json()
            print(json.dumps(tools, indent=2))
        
        print("\n=== Getting Schema ===")
        # Get schema
        async with session.post(
            f"{base_url}/execute",
            json={
                "tool": "graphql_get_schema",
                "arguments": {}
            }
        ) as resp:
            result = await resp.json()
            print(json.dumps(result, indent=2))
        
        print("\n=== Executing Query ===")
        # Execute a query
        async with session.post(
            f"{base_url}/execute",
            json={
                "tool": "graphql_query",
                "arguments": {
                    "query": """
                        {
                            __schema {
                                queryType {
                                    name
                                }
                            }
                        }
                    """
                }
            }
        ) as resp:
            result = await resp.json()
            print(json.dumps(result, indent=2))


# Example 2: Example queries for common GraphQL patterns
def example_queries():
    """Example GraphQL queries"""
    
    examples = {
        "simple_query": {
            "description": "Simple query without variables",
            "query": """
                {
                    users {
                        id
                        name
                        email
                    }
                }
            """
        },
        
        "query_with_variables": {
            "description": "Query with variables",
            "query": """
                query GetUser($id: ID!) {
                    user(id: $id) {
                        id
                        name
                        email
                        posts {
                            title
                            content
                        }
                    }
                }
            """,
            "variables": {
                "id": "123"
            }
        },
        
        "mutation_example": {
            "description": "Mutation to create a new user",
            "mutation": """
                mutation CreateUser($input: CreateUserInput!) {
                    createUser(input: $input) {
                        id
                        name
                        email
                    }
                }
            """,
            "variables": {
                "input": {
                    "name": "John Doe",
                    "email": "john@example.com"
                }
            }
        },
        
        "nested_query": {
            "description": "Nested query with filtering",
            "query": """
                query GetPosts($authorId: ID!, $limit: Int) {
                    posts(authorId: $authorId, limit: $limit) {
                        id
                        title
                        content
                        author {
                            id
                            name
                        }
                        comments {
                            id
                            text
                            author {
                                name
                            }
                        }
                    }
                }
            """,
            "variables": {
                "authorId": "123",
                "limit": 10
            }
        }
    }
    
    print("=== Example GraphQL Queries ===\n")
    for name, example in examples.items():
        print(f"## {name}")
        print(f"Description: {example['description']}")
        print(f"Query/Mutation:\n{example.get('query', example.get('mutation'))}")
        if 'variables' in example:
            print(f"Variables: {json.dumps(example['variables'], indent=2)}")
        print("\n" + "-" * 80 + "\n")


if __name__ == "__main__":
    print("GraphQL MCP Server - Example Usage\n")
    print("=" * 80)
    
    # Show example queries
    example_queries()
    
    # To run HTTP client example, uncomment:
    # asyncio.run(example_http_client())
    
    print("\nTo test with the HTTP server:")
    print("1. Start the server: python server_mcp_http_stateful.py")
    print("2. Run this script with HTTP client enabled")
    print("3. Or use curl commands from README.md")
