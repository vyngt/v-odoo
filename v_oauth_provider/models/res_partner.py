# -*- coding: utf-8 -*-

import uuid

from odoo import api, fields, models


class ResUsers(models.Model):
    _inherit = "res.users"

    oauth_identifier = fields.Char(
        string="OAuth Identifier",
        required=True,
        readonly=True,
        default=lambda self: str(uuid.uuid4()),
        copy=False,
        help="String used to identify this user during an OAuth session.",
    )

    _sql_constraints = [
        (
            "oauth_identifier_unique",
            "UNIQUE (oauth_identifier)",
            "The OAuth identifier of the user must be unique !",
        ),
    ]
