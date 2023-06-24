# -*- coding: utf-8 -*-
import logging

import oauthlib.common

from odoo import http
from odoo.http import request

_logger = logging.getLogger(__name__)


class OAuth2Controller(http.Controller):
    def extract_request(self):
        uri = http.request.httprequest.base_url
        http_method = http.request.httprequest.method
        body = oauthlib.common.urlencode(http.request.httprequest.values.items())
        headers = http.request.httprequest.headers

        return uri, http_method, body, headers

    @http.route(
        "/oauth2/authorize",
        auth="user",
        type="http",
        website=True,
        methods=["GET", "POST"],
    )
    def authorize(self, **kw):
        return request.render("v_oauth_provider.authorize")
