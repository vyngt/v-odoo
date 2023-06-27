from typing import Any

from odoo import api, fields, models


class OAuth2ProviderAuthorizationCode(models.Model):
    _name = "oauth.provider.authorization.code"
    _description = "OAuth Provider Authorization Code"
    _rec_name = "code"

    code = fields.Char(required=True, help="Name of the authorization code.")
    client_id = fields.Many2one(
        comodel_name="oauth.provider.client",
        string="Client",
        required=True,
        help="Client associated to this authorization code.",
    )
    user_id = fields.Many2one(
        comodel_name="res.users",
        string="User",
        required=True,
        help="User associated to this authorization code.",
    )
    redirect_uri_id = fields.Many2one(
        comodel_name="oauth.provider.redirect.uri",
        string="Redirect URI",
        required=True,
        help="Redirect URI associated to this authorization code.",
    )
    scope = fields.Char(
        string="Scopes",
        help="Scopes allowed by this authorization code.",
    )

    active = fields.Boolean(default=True)

    _sql_constraints = [
        (
            "code_client_id_unique",
            "UNIQUE (code, client_id)",
            "The authorization code must be unique per client !",
        ),
    ]
