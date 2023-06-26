# -*- coding: utf-8 -*-
{
    "name": "OAuth2 Provider - JWT Plugin",
    "summary": """OAuth2 Provider - JWT Support""",
    "description": """
        Fun
    """,
    "author": "VyNT",
    "website": "https://github.com/vyngt",
    "category": "V/OAuth",
    "version": "16.0.1.0.0",
    "depends": ["v_oauth_provider"],
    "data": [
        "views/oauth_provider_client.xml",
    ],
    "external_dependencies": {
        "python": ["pyjwt", "cryptography"],
    },
    "license": "LGPL-3",
}  # type: ignore
