# -*- coding: utf-8 -*-
import base64
import hashlib
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidSignatureError,
)
from oauthlib import oauth2
from oauthlib.oauth2.rfc6749.tokens import random_token_generator
from werkzeug.exceptions import InternalServerError  # type: ignore

from odoo import _, api, exceptions, fields, models

from ..oauth.validators import OdooValidator

_logger = logging.getLogger(__name__)


class OAuth2ProviderClient(models.Model):
    _name = "oauth.provider.client"
    _description = "OAuth Provider Client"

    CRYPTOSYSTEMS = {
        "RS": RSAPrivateKey,
        "PS": RSAPrivateKey,
    }

    name = fields.Char("Name", help="Name of this client", required=True)
    identifier = fields.Char(
        string="Client Identifier",
        required=True,
        readonly=True,
        default=lambda self: str(uuid.uuid4()),
        copy=False,
        help="Unique identifier of the client.",
    )

    secret = fields.Char(help="Optional secret used to authenticate the client.")

    issuer = fields.Char(help="Issuer", required=True)

    application_type = fields.Selection(
        selection=[
            ("w", "Web Application"),
            ("l", "Legacy Application"),
        ],
        required=True,
        default="w",
    )

    grant_type = fields.Selection(
        selection=[
            ("authorization_code", "Authorization code"),
            ("password", "Password"),
        ],
        string="Grant Type",
        compute="_compute_grant_response_type",
        store=True,
    )

    response_type = fields.Selection(
        selection=[
            ("code", "Authorization code"),
            ("none", "None"),
        ],
        string="Response Type",
        compute="_compute_grant_response_type",
        store=True,
    )

    scope = fields.Char(
        string="Allowed Scopes",
        help="List of scopes the client is allowed to access.",
        required=True,
    )

    redirect_uri_ids = fields.One2many(
        comodel_name="oauth.provider.redirect.uri",
        inverse_name="client_id",
        string="OAuth Redirect URIs",
        help="Allowed redirect URIs for the client.",
    )

    jwt_algorithm = fields.Selection(
        selection=[
            (
                "RS256",
                "RSASSA-PKCS1-v1_5 signature algorithm using SHA-256 hash algorithm",
            ),
            (
                "RS384",
                "RSASSA-PKCS1-v1_5 signature algorithm using SHA-384 hash algorithm",
            ),
            (
                "RS512",
                "RSASSA-PKCS1-v1_5 signature algorithm using SHA-512 hash algorithm",
            ),
            (
                "PS256",
                "RSASSA-PSS signature using SHA-256 and MGF1 padding with SHA-256",
            ),
            (
                "PS384",
                "RSASSA-PSS signature using SHA-384 and MGF1 padding with SHA-384",
            ),
            (
                "PS512",
                "RSASSA-PSS signature using SHA-512 and MGF1 padding with SHA-512",
            ),
        ],
        default="RS256",
        string="Algorithm",
        help="Algorithm used to sign the JSON Web Token.",
    )
    jwt_private_key = fields.Char(
        string="Private Key",
        help="Private key used for the JSON Web Token generation.",
        trim=False,
    )
    jwt_public_key = fields.Char(
        string="Public Key",
        trim=False,
        compute="_compute_jwt_public_key",
        help="Public key used for the JSON Web Token generation.",
    )

    _sql_constraints = [
        (
            "identifier_unique",
            "UNIQUE (identifier)",
            "The identifier of the client must be unique !",
        ),
    ]

    @api.model
    def application_type_mapping(self):
        return {
            "w": ("authorization_code", "code"),
            "l": ("password", "none"),
        }

    @api.depends("application_type")
    def _compute_grant_response_type(self):
        client: Any
        applications = self.application_type_mapping()
        for client in self:
            client.grant_type, client.response_type = applications[
                client.application_type
            ]

    @api.model
    def _get_secret(self):
        secret: str = (
            self.env["ir.config_parameter"].sudo().get_param("database.secret")
        )
        if not secret:
            raise InternalServerError("database secret is not set!!!")

        return secret.encode()

    def _load_private_key(self):
        """Load the client's private key into a cryptography's object instance"""
        try:
            return load_pem_private_key(
                self.jwt_private_key.encode(),
                password=self._get_secret(),
                backend=default_backend(),
            )
        except ValueError:
            self.jwt_private_key = ""
            return ""

    @api.constrains("jwt_algorithm", "jwt_private_key")
    def _check_jwt_private_key(self):
        """Check if the private key's type matches the selected algorithm

        This check is only performed for asymmetric algorithms
        """
        client: Any

        for client in self:
            algorithm_prefix = client.jwt_algorithm[:2]
            if client.jwt_private_key and algorithm_prefix in self.CRYPTOSYSTEMS:
                private_key = client._load_private_key()

                if not isinstance(private_key, self.CRYPTOSYSTEMS[algorithm_prefix]):
                    raise exceptions.ValidationError(
                        _("The private key doesn't fit the selected algorithm!")
                    )

    def generate_private_key(self):
        """Generate a private key for RSA algorithm clients"""
        client: Any

        for client in self:
            algorithm_prefix = client.jwt_algorithm[:2]

            if algorithm_prefix in ("RS", "PS"):
                key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend(),
                )
            else:
                raise exceptions.UserError(
                    _("You can only generate private keys for asymmetric algorithms!")
                )

            private_key = key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=BestAvailableEncryption(self._get_secret()),
            )

            client.jwt_private_key = private_key.decode()

    def _compute_jwt_public_key(self):
        """Compute the public key associated to the client's private key

        This is only done for asymmetric algorithms
        """
        client: Any

        for client in self:
            if (
                client.jwt_private_key
                and client.jwt_algorithm[:2] in self.CRYPTOSYSTEMS
            ):
                private_key = client._load_private_key()
                public_key = private_key.public_key().public_bytes(
                    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
                )
                client.jwt_public_key = public_key.decode()
            else:
                client.jwt_public_key = False

    def get_oauth2_server(self, validator=None, **kwargs):
        self.ensure_one()

        key = hashlib.sha256(str(datetime.utcnow().timestamp()).encode()).hexdigest()

        def jwt_generator(request):
            payload = self._encode(request, key)

            return jwt.encode(
                payload,
                request.provider._load_private_key(),
                algorithm=request.provider.jwt_algorithm,
            )

        def jwt_refresh_generator(request):
            payload = self._encode(request, key, True)

            return jwt.encode(
                payload,
                request.provider._load_private_key(),
                algorithm=request.provider.jwt_algorithm,
            )

        if validator is None:
            validator = OdooValidator()

        kwargs["token_generator"] = jwt_generator
        kwargs["refresh_token_generator"] = jwt_refresh_generator

        if self.application_type == "authorization_code":
            return oauth2.WebApplicationServer(validator, **kwargs)
        elif self.application_type == "password":
            return oauth2.LegacyApplicationServer(validator, **kwargs)

        return oauth2.Server(validator, **kwargs)

    @api.model
    def _encode(self, request, key, refresh: bool = False):
        utcnow = datetime.utcnow()
        exp = utcnow + timedelta(seconds=36000 if refresh else request.expires_in)

        data = {
            "exp": exp,
            "nbf": utcnow,
            "iss": request.provider.issuer,
            "aud": request.provider.identifier,
            "iat": utcnow,
            "scope": request.provider.scope,
            "type": "normal" if not refresh else "refresh",
            "uid": request.odoo_user.id,
            "jti": key,
        }
        return data

    def _decode(self, encoded):
        try:
            decoded = jwt.decode(
                encoded,
                self.jwt_public_key,
                algorithms=[self.jwt_algorithm],
                issuer=self.issuer,
                audience=self.identifier,
            )
        except (
            ValueError,
            DecodeError,
            InvalidAlgorithmError,
            InvalidSignatureError,
            InvalidAudienceError,
            ExpiredSignatureError,
        ):
            return None

        return decoded

    @api.model
    def perform_decode(self, encoded):
        provider: Any
        providers: Any = self.search([])

        for provider in providers:
            if decoded := provider._decode(encoded):
                return decoded

        return None

    @api.model
    def revoke(self, token):
        Blacklist = self.env["oauth.provider.blacklist"]
        payload = self.env["oauth.provider.client"].perform_decode(token)
        if "jti" in payload:
            if not Blacklist.search([("token_id", "=", payload["jti"])]):
                Blacklist.sudo().create({"token_id": payload["jti"]})

        return True

    @api.model
    def get_provider_by_token(self, token):
        payload = self.perform_decode(token)
        if not payload:
            return None

        try:
            return self.search(
                [
                    ("identifier", "=", payload["aud"]),
                    ("issuer", "=", payload["iss"]),
                ],
                limit=1,
            )
        except KeyError:
            return None
