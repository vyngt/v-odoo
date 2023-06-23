from oauthlib.common import Request
from oauthlib.oauth2 import RequestValidator, WebApplicationServer

from odoo.http import request

# from ..models.oauth import OAuthClient


class OdooRequestValidator(RequestValidator):
    def validate_client_id(self, client_id: str, _request: Request, *args, **kwargs):
        client = (
            request.env["oauth.client"]
            .sudo()
            .search([("client_id", "=", client_id)], limit=1)
        )

        return True if client else False


validator = OdooRequestValidator()

server = WebApplicationServer(validator)
