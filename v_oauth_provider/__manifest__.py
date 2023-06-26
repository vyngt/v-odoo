# -*- coding: utf-8 -*-
{
    "name": "OAuth2 Provider",
    "summary": """OAuth2 Provider""",
    "description": """
        <p>OAuth2 Provider</p>
        <p>ref: https://github.com/OCA/server-tools/tree/9.0/oauth_provider</p>
    """,
    "author": "VyNT",
    "website": "https://gitthub.com/vyngt",
    "category": "V/OAuth",
    "version": "16.0.1.0.0",
    "depends": ["v"],
    "data": [
        "security/oauth_provider_security.xml",
        "security/ir.model.access.csv",
        "views/templates.xml",
        "views/oauth_provider_view.xml",
        "views/oauth_provider_client_view.xml",
    ],
    "license": "LGPL-3",
    "pre_init_hook": "pre_init_hook",
    "external_dependencies": {
        "python": ["oauthlib", "pyjwt", "cryptography"],
    },
    "application": True,
}  # type: ignore
