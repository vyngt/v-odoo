from typing import Any

from odoo import _, api, exceptions, fields, models


class OAuth2ProviderToken(models.Model):
    _name = "oauth.provider.token"
    _description = "OAuth Provider Token"
    _rec_name = "access_token"

    user_id = fields.Many2one("res.users", string="User", required=True)
    client_id = fields.Many2one(
        "oauth.provider.client", string="OAuth Client", required=True
    )

    scopes = fields.Text("Scopes", translate=False)

    access_token = fields.Char("Access Token", required=True)
    refresh_token = fields.Char("Refresh Token")
    expires_at = fields.Datetime("Expires at", required=True)

    active = fields.Boolean(
        compute="_compute_active",
        search="_search_active",
        help="A token is active only if it has not yet expired.",
    )

    _sql_constraints = [
        ("oauth_access_token_unique", "UNIQUE(access_token)", "Must Unique"),
        ("oauth_refresh_token_unique", "UNIQUE(refresh_token)", "Must Unique"),
    ]

    def _compute_active(self):
        token: Any

        for token in self:
            token.active = fields.Datetime.now() < token.expires_at

    @api.model
    def _search_active(self, operator, operand):
        domain = []
        if operator == "in":
            if True in operand:
                domain += self._search_active("=", True)
            if False in operand:
                domain += self._search_active("=", False)
            if len(domain) > 1:
                domain = [(1, "=", 1)]
        elif operator == "not in":
            if True in operand:
                domain += self._search_active("!=", True)
            if False in operand:
                domain += self._search_active("!=", False)
            if len(domain) > 1:
                domain = [(0, "=", 1)]
        elif operator in ("=", "!="):
            operators = {
                ("=", True): ">",
                ("=", False): "<=",
                ("!=", False): ">",
                ("!=", True): "<=",
            }
            domain = [
                ("expires_at", operators[operator, operand], fields.Datetime.now())
            ]
        else:
            raise exceptions.UserError(
                _("Invalid operator {operator} for  field active!").format(
                    operator=operator
                )
            )

        return domain

    def generate_user_id(self):
        # TODO
        self.ensure_one()

        return False

    def get_data_for_model(self):
        # TODO
        self.ensure_one()

        return False
