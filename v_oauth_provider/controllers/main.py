# -*- coding: utf-8 -*-
import json
import logging
from datetime import datetime
from typing import Any

import oauthlib.common
import werkzeug.utils  # type: ignore
import werkzeug.wrappers  # type: ignore
from oauthlib import oauth2

from odoo import fields, http
from odoo.addons.web.controllers.main import ensure_db
from odoo.http import request

_logger = logging.getLogger(__name__)


class OAuth2ProviderController(http.Controller):
    def __init__(self):
        super(OAuth2ProviderController, self).__init__()

    def _get_request_information(self):
        """Retrieve needed arguments for oauthlib methods"""
        uri = request.httprequest.base_url
        http_method = request.httprequest.method
        body = oauthlib.common.urlencode(request.httprequest.values.items())
        headers = request.httprequest.headers

        return uri, http_method, body, headers

    def _check_access_token(self, access_token):
        """Check if the provided access token is valid"""
        token = request.env["oauth.provider.token"].search(
            [
                ("token", "=", access_token),
            ]
        )
        if not token:
            return False

        oauth2_server = token.client_id.get_oauth2_server()
        # Retrieve needed arguments for oauthlib methods
        uri, http_method, body, headers = self._get_request_information()

        # Validate request information
        valid, oauthlib_request = oauth2_server.verify_request(
            uri, http_method=http_method, body=body, headers=headers
        )

        if valid:
            return token

        return False

    def _json_response(self, data=None, status=200, headers=None):
        """Returns a json response to the client"""
        if headers is None:
            headers = {"Content-Type": "application/json"}

        return werkzeug.wrappers.Response(
            json.dumps(data), status=status, headers=headers
        )

    @http.route("/oauth2/authorize", type="http", auth="user", methods=["GET"])
    def authorize(
        self,
        client_id=None,
        response_type=None,
        redirect_uri=None,
        scope=None,
        state=None,
        *args,
        **kwargs
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
            request.httpsession["oauth_scopes"] = scopes
            request.httpsession["oauth_credentials"] = {
                "client_id": credentials["client_id"],
                "redirect_uri": credentials["redirect_uri"],
                "response_type": credentials["response_type"],
                "state": credentials["state"],
            }
            if client.skip_authorization:
                # Skip the authorization page
                # Useful when the application is trusted
                return self.authorize_post()
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

        oauth_scopes = client.scope_ids.filtered(lambda record: record.code in scopes)
        return request.render(
            "v_oauth_provider.authorization",
            {
                "oauth_client": client.name,
                "oauth_scopes": oauth_scopes,
            },
        )

    @http.route("/oauth2/authorize", type="http", auth="user", methods=["POST"])
    def authorize_post(self, *args, **kwargs):
        """Redirect to the requested URI during the authorization"""
        client = request.env["oauth.provider.client"].search(
            [
                (
                    "identifier",
                    "=",
                    request.httpsession.get("oauth_credentials", {}).get("client_id"),
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
        scopes = request.httpsession["oauth_scopes"]
        credentials = request.httpsession["oauth_credentials"]
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
        **kwargs
    ):
        """Return a token corresponding to the supplied information

        Not all parameters are required, depending on the application type
        """
        ensure_db()

        # If no client_id is specified, get it from session
        if client_id is None:
            client_id = request.httpsession.get("oauth_credentials", {}).get(
                "client_id"
            )

        client = (
            request.env["oauth.provider.client"]
            .sudo()
            .search(
                [
                    ("identifier", "=", client_id),
                ]
            )
        )

        if not client:
            return self._json_response(data={"error": "invalid_client_id"}, status=401)
        oauth2_server = client.get_oauth2_server()

        # Retrieve needed arguments for oauthlib methods
        uri, http_method, body, headers = self._get_request_information()
        credentials = {"scope": scope}

        # Retrieve the authorization code, if any, to get Odoo's user id
        existing_code = request.env["oauth.provider.authorization.code"].search(
            [
                ("client_id.identifier", "=", client_id),
                ("code", "=", code),
            ]
        )
        if existing_code:
            credentials["odoo_user_id"] = existing_code.user_id.id
        # Retrieve the existing token, if any, to get Odoo's user id
        existing_token = request.env["oauth.provider.token"].search(
            [
                ("client_id.identifier", "=", client_id),
                ("refresh_token", "=", refresh_token),
            ]
        )
        if existing_token:
            credentials["odoo_user_id"] = existing_token.user_id.id

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
        token = self._check_access_token(access_token)
        if not token:
            return self._json_response(
                data={"error": "invalid_or_expired_token"}, status=401
            )

        token_lifetime = (
            fields.Datetime.from_string(token.expires_at) - datetime.now()  # type: ignore
        ).seconds
        # Base data to return
        data = {
            "audience": token.client_id.identifier,
            "scopes": " ".join(token.scope_ids.mapped("code")),
            "expires_in": token_lifetime,
        }

        # Add the oauth user identifier, if user's information access is
        # allowed by the token's scopes
        user_data = token.get_data_for_model("res.users", res_id=token.user_id.id)
        if "id" in user_data:
            data.update(user_id=token.generate_user_id())
        return self._json_response(data=data)

    @http.route("/oauth2/userinfo", type="http", auth="none", methods=["GET"])
    def userinfo(self, access_token=None, *args, **kwargs):
        """Return some information about the user linked to the supplied token

        Similar to Google's "userinfo" request
        """
        ensure_db()
        token = self._check_access_token(access_token)
        if not token:
            return self._json_response(
                data={"error": "invalid_or_expired_token"}, status=401
            )

        data = token.get_data_for_model("res.users", res_id=token.user_id.id)
        return self._json_response(data=data)

    @http.route("/oauth2/otherinfo", type="http", auth="none", methods=["GET"])
    def otherinfo(self, access_token=None, model=None, *args, **kwargs):
        """Return allowed information about the requested model"""
        ensure_db()
        token = self._check_access_token(access_token)
        if not token:
            return self._json_response(
                data={"error": "invalid_or_expired_token"}, status=401
            )

        model_obj = request.env["ir.model"].search(
            [
                ("model", "=", model),
            ]
        )
        if not model_obj:
            return self._json_response(data={"error": "invalid_model"}, status=400)

        data = token.get_data_for_model(model)
        return self._json_response(data=data)

    @http.route("/oauth2/revoke_token", type="http", auth="none", methods=["POST"])
    def revoke_token(self, token=None, *args, **kwargs):
        """Revoke the supplied token"""
        ensure_db()
        body = oauthlib.common.urlencode(request.httprequest.values.items())
        db_token = request.env["oauth.provider.token"].search(
            [
                ("token", "=", token),
            ]
        )
        if not db_token:
            db_token = request.env["oauth.provider.token"].search(
                [
                    ("refresh_token", "=", token),
                ]
            )
        if not db_token:
            return self._json_response(
                data={"error": "invalid_or_expired_token"}, status=401
            )
        oauth2_server = db_token.client_id.get_oauth2_server()

        # Retrieve needed arguments for oauthlib methods
        uri, http_method, body, headers = self._get_request_information()

        headers, body, status = oauth2_server.create_revocation_response(
            uri, http_method=http_method, body=body, headers=headers
        )
        return werkzeug.wrappers.Response(body, status=status, headers=headers)
