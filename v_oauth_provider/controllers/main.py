# -*- coding: utf-8 -*-
import logging

from odoo import http
from odoo.http import request

from ..oauth.validators import server

_logger = logging.getLogger(__name__)


class Authorization(http.Controller):
    _authorization_endpoint = server

    def extract_request(self):
        params = request.get_http_params()
        uri = params.get("uri")
        method = request.httprequest.method
        body = None
        headers = request.httprequest.headers

        return uri, method, body, headers

    @http.route(
        "/authorize", auth="user", type="http", website=True, methods=["GET", "POST"]
    )
    def authorize(self, **kw):
        _logger.info(f"{dir(request.httprequest)}")

        uri, method, body, headers = self.extract_request()

        _logger.info(f"{list(headers)}")

        x = self._authorization_endpoint.validate_authorization_request(
            uri, method, body, headers
        )

        _logger.info(f"Echo {x}")

        return request.render("v_oauth_provider.authorize")

    # @http.route("/token")
    # def token(self, **kw):
    #     return request.render()
