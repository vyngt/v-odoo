from odoo import api, fields, models


class OAuth2ProviderBlacklist(models.Model):
    _name = "oauth.provider.blacklist"
    _description = "For RevocationToken Action"

    token_id = fields.Char("JTI", required=True)
    active = fields.Boolean(default=True)
