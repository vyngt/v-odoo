# -*- coding: utf-8 -*-

from odoo import api, fields, models


class OAuthClient(models.Model):
    _name = "oauth.client"
    _description = "OAuth Client"

    client_id = fields.Char("Client ID")
    user_id = fields.Many2one("res.users", string="User")
    grant_type = fields.Selection(
        selection=[
            ("authorization_code", "Authorization code"),
        ],
        string="Grant Type",
    )
    response_type = fields.Selection(
        selection=[
            ("code", "Authorization code"),
        ],
        string="Response Type",
    )
    scopes = fields.Text("Scope", translate=False)
    redirect_uris = fields.Text("Redirect URLs", translate=False)

    _sql_constraints = [("oauth_client_id", "UNIQUE(client_id)", "Must Unique")]


class OAuthBearerToken(models.Model):
    _name = "oauth.token"
    _description = "OAuth Bearer Token"

    user_id = fields.Many2one("res.users", string="User")
    oauth_client_id = fields.Many2one("oauth.client", string="OAuth Client")
    scopes = fields.Text("Scopes", translate=False)
    access_token = fields.Char("Access Token")
    refresh_token = fields.Char("Refresh Token")
    expires_at = fields.Datetime("Expires at")

    _sql_constraints = [
        ("oauth_access_token_unique", "UNIQUE(access_token)", "Must Unique"),
        ("oauth_refresh_token_unique", "UNIQUE(refresh_token)", "Must Unique"),
    ]


class OAuthAuthorizationCode(models.Model):
    _name = "oauth.authorization.code"
    _description = "OAuth Authorization Code"

    user_id = fields.Many2one("res.users", string="User")
    oauth_client_id = fields.Many2one("oauth.client", string="OAuth Client")
    scopes = fields.Text("Scopes", translate=False)
    redirect_uri = fields.Text("Redirect URL", translate=False)
    code = fields.Char("Code")
    expires_at = fields.Datetime("Expires at")

    # PKCE
    _sql_constraints = [("oauth_code", "UNIQUE(code)", "Must Unique")]
