import base64
import logging
from datetime import datetime, timedelta

from oauthlib.common import Request
from oauthlib.oauth2 import Client, RequestValidator

from odoo import fields, http

_logger = logging.getLogger(__name__)


class OdooValidator(RequestValidator):
    def _load_client(self, request, client_id=None):
        """Returns a client instance for the request"""
        client = request.client
        if not client:
            request.provider = http.request.env["oauth.provider.client"].search(
                [
                    ("identifier", "=", client_id or request.client_id),
                ]
            )
            request.client = Client(request.provider.identifier)
            request.odoo_user = http.request.env.user

    def _extract_auth(self, request):
        """Extract auth string from request headers"""
        auth = request.headers.get("Authorization", " ")
        auth_type, auth_string = auth.split(" ", 1)
        if auth_type != "Basic":
            return ""

        return auth_string

    def authenticate_client(self, request, *args, **kwargs):
        """Authenticate the client"""
        _logger.info("Authenticate Client ID")
        auth_string = self._extract_auth(request)
        auth_string_decoded = base64.b64decode(auth_string).decode()

        # If we don't have a proper auth string, get values in the request body
        if ":" not in auth_string_decoded:
            client_id = request.client_id
            client_secret = request.client_secret
        else:
            client_id, client_secret = auth_string_decoded.split(":", 1)
            request.client_id = client_id

        self._load_client(request, client_id)
        return (request.provider.identifier == client_id) and (
            request.provider.secret or ""
        ) == (client_secret or "")

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """Ensure client_id belong to a non-confidential client"""
        _logger.info("Authenticate Client ID")

        self._load_client(request, client_id=client_id)
        return bool(request.provider)

    def client_authentication_required(self, request, *args, **kwargs):
        """Determine if the client authentication is required for the request"""
        _logger.info("Authenticate Client Required")

        if self._extract_auth(request):
            return True

        self._load_client(request)
        return (
            request.provider.grant_type
            in (
                "password",
                "authorization_code",
                "refresh_token",
            )
            or request.client_secret
            or not request.odoo_user.active
        )

    def confirm_redirect_uri(
        self, client_id, code, redirect_uri, client, *args, **kwargs
    ):
        """Ensure that the authorization process' redirect URI

        The authorization process corresponding to the code must begin by using
        this redirect_uri
        """
        code = http.request.env["oauth.provider.authorization.code"].search(
            [
                ("client_id.identifier", "=", client_id),
                ("code", "=", code),
            ]
        )
        return redirect_uri == code.redirect_uri_id.name

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """Returns the default redirect URI for the client"""
        client = http.request.env["oauth.provider.client"].search(
            [
                ("identifier", "=", client_id),
            ]
        )
        return client.redirect_uri_ids and client.redirect_uri_ids[0].name or ""

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        """Returns a list of default scopes for the client"""
        client = http.request.env["oauth.provider.client"].search(
            [
                ("identifier", "=", client_id),
            ]
        )
        return " ".join(s.lower() for s in client.scope.split())

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        """Returns the list of scopes associated to the refresh token"""
        # TODO
        token = refresh_token

        return "profile"

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        """Invalidates an authorization code"""
        code = http.request.env["oauth.provider.authorization.code"].search(
            [
                ("client_id.identifier", "=", client_id),
                ("code", "=", code),
            ]
        )
        code.sudo().write({"active": False})

    def is_within_original_scope(
        self, request_scopes, refresh_token, request, *args, **kwargs
    ):
        """Check if the requested scopes are within a scope of the token"""

        return True

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        """Revoke an access of refresh token"""
        request.provider.revoke(token)

        return True

    def rotate_refresh_token(self, request):
        """Determine if the refresh token has to be renewed

        Called after refreshing an access token
        Always refresh the token by default, but child classes could override
        this method to change this behavior.
        """

        http.request.env["oauth.provider.blacklist"].sudo().create(
            {"token_id": request.old_token_id}
        )
        return True

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        """Store the authorization code into the database"""
        redirect_uri = http.request.env["oauth.provider.redirect.uri"].search(
            [
                ("name", "=", request.redirect_uri),
            ],
            limit=1,
        )
        code = (
            http.request.env["oauth.provider.authorization.code"]
            .sudo()
            .create(
                {
                    "code": code["code"],
                    "client_id": request.provider.id,
                    "user_id": request.odoo_user.id,
                    "redirect_uri_id": redirect_uri.id,
                    "scope": request.provider.scope,
                }
            )
        )

    def save_bearer_token(self, token, request, *args, **kwargs):
        """Store the bearer token into the database"""
        if isinstance(token["access_token"], bytes):
            token["access_token"] = token["access_token"].decode()

        if isinstance(token["refresh_token"], bytes):
            token["refresh_token"] = token["refresh_token"].decode()

        return request.provider.redirect_uri_ids[0].name

    def validate_bearer_token(self, token, scopes, request):
        """Ensure the supplied bearer token is valid, and allowed for the scopes"""
        return True

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """Ensure client_id belong to a valid and active client"""
        self._load_client(request)
        return bool(request.provider)

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        """Check that the code is valid, and assigned to the given client"""
        code = http.request.env["oauth.provider.authorization.code"].search(
            [
                ("client_id.identifier", "=", client_id),
                ("code", "=", code),
            ]
        )

        request.odoo_user = code.user_id
        return bool(code)

    def validate_grant_type(
        self, client_id, grant_type, client, request, *args, **kwargs
    ):
        """Ensure the client is authorized to use the requested grant_type"""
        return client.client_id == client_id and grant_type in (
            request.provider.grant_type,
            "refresh_token",
        )

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        """Ensure the client is allowed to use the requested redirect_uri"""
        return (
            request.provider.identifier == client_id
            and redirect_uri in request.provider.mapped("redirect_uri_ids.name")
        )

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        payload = request.provider.perform_decode(refresh_token)
        if not payload:
            return False
        if "jti" not in payload or http.request.env["oauth.provider.blacklist"].search(
            [("token_id", "=", payload["jti"])]
        ):
            return False

        if "iss" not in payload or payload["iss"] != request.provider.issuer:
            return False

        if (
            "type" not in payload
            or payload["type"] != "refresh"
            or "uid" not in payload
            or not payload["uid"]
        ):
            return False

        if user := http.request.env["res.users"].browse([payload["uid"]]).exists():
            request.odoo_user = user

        request.old_token_id = payload["jti"]

        return "aud" in payload and payload["aud"] == client.client_id

    def validate_response_type(
        self, client_id, response_type, client, request, *args, **kwargs
    ):
        """Ensure the client is allowed to use the requested response_type"""
        return (
            request.provider.identifier == client_id
            and response_type == request.provider.response_type
        )

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        """Ensure the client is allowed to access all requested scopes"""
        # TODO: Validate SCOPE
        return True

    def validate_user(self, username, password, client, request, *args, **kwargs):
        """Ensure the username and password are valid"""
        uid = http.request.session.authenticate(
            http.request.session.db, username, password
        )
        request.odoo_user = http.request.env["res.users"].browse(uid)
        return bool(uid)
