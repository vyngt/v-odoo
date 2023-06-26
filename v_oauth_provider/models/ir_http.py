import re

from werkzeug.exceptions import Unauthorized  # type: ignore

from odoo import models
from odoo.http import request

AUTHORIZATION_RE = re.compile(r"^Bearer ([^ ]+)$")


class IrHttpBearer(models.AbstractModel):
    _inherit = "ir.http"

    @classmethod
    def _auth_method_bearer(cls):
        bearer_token = cls._get_bearer_token()

        token = request.env["oauth.provider.token"].search(
            [("token", "=", bearer_token)]
        )

        if not token.active:
            raise Unauthorized()

        request.update_env(user=token.user_id.id)
        request.token = token.sudo()

    @classmethod
    def _get_bearer_token(cls):
        authorization = request.httprequest.environ.get("HTTP_AUTHORIZATION")

        if not authorization:
            raise Unauthorized()

        mo = AUTHORIZATION_RE.match(authorization)
        if not mo:
            raise Unauthorized()

        return mo.group(1)
