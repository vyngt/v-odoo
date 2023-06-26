# -*- coding: utf-8 -*-

import hashlib
import logging
import uuid

from oauthlib import oauth2

from odoo import api, fields, models

from ..oauth.validators import OdooValidator

_logger = logging.getLogger(__name__)


class OAuth2ProviderClient(models.Model):
    _name = "oauth.provider.client"
    _description = "OAuth Provider Client"

    name = fields.Char("Name", help="Name of this client", required=True)
    identifier = fields.Char(
        string="Client Identifier",
        required=True,
        readonly=True,
        default=lambda self: str(uuid.uuid4()),
        copy=False,
        help="Unique identifier of the client.",
    )

    secret = fields.Char(help="Optional secret used to authenticate the client.")

    grant_type = fields.Selection(
        selection=[
            ("authorization_code", "Authorization code"),
        ],
        string="Grant Type",
        required=True,
    )

    response_type = fields.Selection(
        selection=[
            ("code", "Authorization code"),
        ],
        string="Response Type",
        required=True,
    )

    scope_ids = fields.Many2many(
        comodel_name="oauth.provider.scope",
        string="Allowed Scopes",
        help="List of scopes the client is allowed to access.",
    )

    redirect_uri_ids = fields.One2many(
        comodel_name="oauth.provider.redirect.uri",
        inverse_name="client_id",
        string="OAuth Redirect URIs",
        help="Allowed redirect URIs for the client.",
    )

    token_type = fields.Selection(
        selection=[("random", "Randomly generated")],
        required=True,
        default="random",
        help="Type of token to return. The base module only provides randomly "
        "generated tokens.",
    )

    _sql_constraints = [
        (
            "identifier_unique",
            "UNIQUE (identifier)",
            "The identifier of the client must be unique !",
        ),
    ]

    def get_oauth2_server(self, validator=None, **kwargs):
        self.ensure_one()

        if validator is None:
            validator = OdooValidator()

        return oauth2.WebApplicationServer(validator, **kwargs)

    def generate_user_id(self, user):
        self.ensure_one()

        app_identifier = self.identifier if self.identifier else ""
        user_identifier = user.sudo().oauth_identifier
        user_identifier = user_identifier if user_identifier else ""

        combine = app_identifier + user_identifier

        # Use a sha256 to avoid a too long final string
        return hashlib.sha256(combine.encode()).hexdigest()
