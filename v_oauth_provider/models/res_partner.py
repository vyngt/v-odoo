# -*- coding: utf-8 -*-

from odoo import api, fields, models


class ResUsers(models.Model):
    _inherit = "res.users"

    oauth_client = fields.One2many(
        "oauth.client", inverse_name="user_id", string="OAuth Client"
    )
