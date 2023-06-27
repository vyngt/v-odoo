import logging
import re
from datetime import datetime

from werkzeug.exceptions import Unauthorized  # type: ignore

from odoo import models
from odoo.http import request

AUTHORIZATION_RE = re.compile(r"^Bearer ([^ ]+)$")


class IrHttpBearer(models.AbstractModel):
    _inherit = "ir.http"

    @classmethod
    def _auth_method_jwt(cls):
        token = cls._get_bearer_token()

        try:
            payload = cls._extract_payload(token)

            if (
                not payload
                or not payload["jti"]
                or payload["exp"] < datetime.utcnow().timestamp()
                or request.env["oauth.provider.blacklist"].search(
                    [("token_id", "=", payload["jti"])]
                )
            ):
                raise Unauthorized("Unauthorized")

            if payload["type"] == "normal" and payload["uid"]:
                request.update_env(user=payload["uid"])
            else:
                raise Unauthorized("Unauthorized")
        except KeyError:
            raise Unauthorized("Unauthorized")

    @classmethod
    def _get_bearer_token(cls):
        authorization = request.httprequest.environ.get("HTTP_AUTHORIZATION")

        if not authorization:
            raise Unauthorized()

        mo = AUTHORIZATION_RE.match(authorization)
        if not mo:
            raise Unauthorized()

        return mo.group(1)

    @classmethod
    def _extract_payload(cls, token):
        return request.env["oauth.provider.client"].perform_decode(token)
