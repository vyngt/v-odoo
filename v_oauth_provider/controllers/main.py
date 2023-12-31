# -*- coding: utf-8 -*-
import base64
import json
import logging
from datetime import datetime
from typing import Any

import oauthlib.common
import werkzeug.utils  # type: ignore
import werkzeug.wrappers  # type: ignore
from oauthlib import oauth2

from odoo import fields, http
from odoo.addons.web.controllers.utils import ensure_db
from odoo.http import request

from ..oauth.validators import OdooValidator

_logger = logging.getLogger(__name__)


class OAuth2ProviderController(http.Controller):
    def _get_request_information(self):
        """Retrieve needed arguments for oauthlib methods"""
        uri = request.httprequest.base_url
        http_method = request.httprequest.method
        body = oauthlib.common.urlencode(request.httprequest.values.items())
        headers = request.httprequest.headers

        return uri, http_method, body, headers

    def _get_client_id(self, headers):
        auth = headers.get("Authorization", " ")
        auth_type, auth_string = auth.split(" ", 1)
        if auth_type != "Basic":
            return None

        auth_string_decoded = base64.b64decode(auth_string).decode()
        if ":" not in auth_string_decoded:
            return None
        else:
            client_id, _ = auth_string_decoded.split(":", 1)

        return client_id

    def _json_response(self, data=None, status=200, headers=None):
        """Returns a json response to the client"""
        if headers is None:
            headers = {"Content-Type": "application/json"}

        return werkzeug.wrappers.Response(
            json.dumps(data), status=status, headers=headers
        )

    @http.route(
        "/oauth2/authorize", type="http", auth="user", methods=["GET"], website=True
    )
    def authorize(
        self,
        client_id=None,
        response_type=None,
        redirect_uri=None,
        scope=None,
        state=None,
        *args,
        **kwargs,
    ):
        """Check client's request, and display an authorization page to the user,

        The authorization page lists allowed scopes
        If the client is configured to skip the authorization page, directly
        redirects to the requested URI
        """
        client = request.env["oauth.provider.client"].search(
            [
                ("identifier", "=", client_id),
            ]
        )
        if not client:
            return request.render(
                "v_oauth_provider.authorization_error",
                {
                    "title": "Unknown Client Identifier!",
                    "message": "This client identifier is invalid.",
                },
            )
        oauth2_server = client.get_oauth2_server()

        # Retrieve needed arguments for oauthlib methods
        uri, http_method, body, headers = self._get_request_information()
        try:
            scopes, credentials = oauth2_server.validate_authorization_request(
                uri, http_method=http_method, body=body, headers=headers
            )

            # Store only some values, because the pickling of the full request
            # object is not possible
            request.session["oauth_scopes"] = scopes
            request.session["oauth_credentials"] = {
                "client_id": credentials["client_id"],
                "redirect_uri": credentials["redirect_uri"],
                "response_type": credentials["response_type"],
                "state": credentials["state"],
            }

        except oauth2.FatalClientError as e:
            return request.render(
                "v_oauth_provider.authorization_error",
                {
                    "title": "Error: {error}".format(error=e.error),
                    "message": e.description,
                },
            )
        except oauth2.OAuth2Error as e:
            return request.render(
                "v_oauth_provider.authorization_error",
                {
                    "title": "Error: {error}".format(error=e.error),
                    "message": "An unknown error occurred! Please contact your "
                    "administrator",
                },
            )

        oauth_scopes = client.scope
        return request.render(
            "v_oauth_provider.authorization",
            {
                "oauth_client": client.name,
                "oauth_scopes": oauth_scopes,
            },
        )

    @http.route(
        "/oauth2/authorize", type="http", auth="user", methods=["POST"], website=True
    )
    def authorize_post(self, *args, **kwargs):
        """Redirect to the requested URI during the authorization"""
        client = request.env["oauth.provider.client"].search(
            [
                (
                    "identifier",
                    "=",
                    request.session.get("oauth_credentials", {}).get("client_id"),
                )
            ]
        )
        if not client:
            return request.render(
                "v_oauth_provider.authorization_error",
                {
                    "title": "Unknown Client Identifier!",
                    "message": "This client identifier is invalid.",
                },
            )
        oauth2_server = client.get_oauth2_server()

        # Retrieve needed arguments for oauthlib methods
        uri, http_method, body, headers = self._get_request_information()
        scopes = request.session["oauth_scopes"]
        credentials = request.session["oauth_credentials"]

        headers, body, status = oauth2_server.create_authorization_response(
            uri,
            http_method=http_method,
            body=body,
            headers=headers,
            scopes=scopes,
            credentials=credentials,
        )

        return werkzeug.utils.redirect(headers["Location"], code=status)

    @http.route("/oauth2/token", type="http", auth="none", methods=["POST"], csrf=False)
    def token(
        self,
        client_id=None,
        client_secret=None,
        redirect_uri=None,
        scope=None,
        code=None,
        grant_type=None,
        username=None,
        password=None,
        refresh_token=None,
        *args,
        **kwargs,
    ):
        """Return a token corresponding to the supplied information

        Not all parameters are required, depending on the application type
        """
        ensure_db()

        uri, http_method, body, headers = self._get_request_information()

        if not client_id:
            client_id = self._get_client_id(headers)

        credentials = {"scope": scope}
        oauth2_server = None

        if code:
            existing_code = request.env["oauth.provider.authorization.code"].search(
                [
                    ("client_id.identifier", "=", client_id),
                    ("code", "=", code),
                ],
                limit=1,
            )
            credentials["odoo_user_id"] = existing_code.user_id.id
            oauth2_server = existing_code.client_id.get_oauth2_server()
        elif refresh_token or client_id:
            client = request.env["oauth.provider.client"].search(
                [("identifier", "=", client_id)], limit=1
            )
            if client:
                oauth2_server = client.get_oauth2_server()

        if not oauth2_server:
            return self._json_response(data={"error": "invalid_client_id"}, status=401)

        headers, body, status = oauth2_server.create_token_response(
            uri,
            http_method=http_method,
            body=body,
            headers=headers,
            credentials=credentials,
        )

        return werkzeug.wrappers.Response(body, status=status, headers=headers)

    @http.route("/oauth2/tokeninfo", type="http", auth="none", methods=["GET"])
    def tokeninfo(self, access_token=None, *args, **kwargs):
        """Return some information about the supplied token

        Similar to Google's "tokeninfo" request
        """
        ensure_db()
        data = {"active": False}

        return self._json_response(data=data)

    @http.route("/oauth2/userinfo", type="http", auth="jwt", methods=["GET"])
    def userinfo(self, *args, **kwargs):
        """Return some information about the user linked to the supplied token"""
        ensure_db()
        base_url = request.env["ir.config_parameter"].sudo().get_param("web.base.url")

        data = {
            "id": request.env.user.id,
            "name": request.env.user.name,
            "email": request.env.user.email,
            "image": f"{base_url}/web/image/res.users/{request.env.user.id}/image_512",
        }

        return self._json_response(data=data)

    @http.route(
        "/oauth2/revoke_token", type="http", auth="none", methods=["POST"], csrf=False
    )
    def revoke_token(self, token=None, *args, **kwargs):
        """Revoke the supplied token"""
        ensure_db()

        client = request.env["oauth.provider.client"]

        if not token:
            return self._json_response(data={"error": "missing token"}, status=401)

        decoded = client.perform_decode(token)

        if not decoded or "jti" not in decoded:
            return self._json_response(data={"error": "invalid token"}, status=401)

        _client = client.sudo().search(
            [
                ("identifier", "=", decoded["aud"]),
                ("issuer", "=", decoded["iss"]),
            ],
            limit=1,
        )

        if not _client:
            return self._json_response(data={"error": "invalid token"}, status=401)

        client_id = oauthlib.common.urlencode({"client_id": _client.identifier}.items())

        oauth2_server = _client.get_oauth2_server()

        # Retrieve needed arguments for oauthlib methods
        uri, http_method, body, headers = self._get_request_information()

        body += f"&{client_id}"

        headers, body, status = oauth2_server.create_revocation_response(
            uri, http_method=http_method, body=body, headers=headers
        )
        return werkzeug.wrappers.Response(body, status=status, headers=headers)

    @http.route(
        "/oauth2/.well-known/oauth-authorization-server",
        type="http",
        auth="none",
        methods=["GET"],
    )
    def metadata_endpoint(self, **kw):
        base_url = request.env["ir.config_parameter"].sudo().get_param("web.base.url")
        if not oauth2.is_secure_transport(base_url):
            return self._json_response(
                data={"error": "this endpoint not ready"}, status=503
            )

        oauth_web_server = oauth2.WebApplicationServer(OdooValidator())

        endpoint = oauth2.MetadataEndpoint(
            [oauth_web_server],
            claims={
                "issuer": base_url,
                "authorization_endpoint": f"{base_url}/oauth2/authorize",
                "token_endpoint": f"{base_url}/oauth2/token",
                "revocation_endpoint": f"{base_url}/oauth2/revoke_token",
                "introspection_endpoint": f"{base_url}/oauth2/tokeninfo",
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "response_types_supported": [
                    "code",
                ],
            },
        )
        uri, http_method, body, headers = self._get_request_information()

        headers, body, status = endpoint.create_metadata_response(
            uri, http_method, body, headers
        )

        return werkzeug.wrappers.Response(body, status=status, headers=headers)
