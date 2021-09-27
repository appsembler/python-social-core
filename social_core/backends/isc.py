"""
Backend for InterSystems OAuth 2.0 login service
"""
import re
import jwt
import base64
from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import AuthCanceled

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend


class BaseISCAuth(object):
    def setting(self, name, default=None):
        """Return setting value from strategy"""
        return self.strategy.setting(name, default=default, backend=self)

    def get_user_id(self, details, response):
        """Use isc username as unique id"""
        return details["username"]

    def get_user_details(self, response):
        """Get the username form ISC OAuth"""
        user_data = response.get("user_data")
        username, email, fullname = (
            user_data.get("sub", ""),
            user_data.get("email", ""),
            user_data.get("name", ""),
        )

        return {"username": username, "email": email, "fullname": fullname}

    def get_isc_public_key(self):
        certificate = load_pem_x509_certificate(
            self.setting("SOCIAL_AUTH_ISC_SERVER_CERT").encode(), default_backend()
        )
        return certificate.public_key()


class BaseISCOAuth2API(BaseISCAuth):
    def get_scope(self):
        """Return list with needed access scope"""
        scope = self.setting("SCOPE", [])
        if not self.setting("IGNORE_DEFAULT_SCOPE", False):
            default_scope = []
            if self.setting("USE_DEPRECATED_API", False):
                default_scope = self.DEPRECATED_DEFAULT_SCOPE
            else:
                default_scope = self.DEFAULT_SCOPE
            scope = scope + (default_scope or [])
        return scope

    def user_data(self, access_token, *args, **kwargs):
        """Return user data from ISC API"""
        url = "https://login.intersystems.com/uat/oauth2/userinfo"
        encoded_response = self.request(
            url, params={"access_token": access_token, "alt": "json"}
        )
        client_id, secret = self.get_key_and_secret()
        return jwt.decode(
            encoded_response.text, self.get_isc_public_key(), audience=client_id
        )

    def revoke_token_params(self, token, uid):
        return {"token": token}

    def revoke_token_headers(self, token, uid):
        return {"Content-type": "application/json"}


class ISCOAuth2(BaseISCOAuth2API, BaseOAuth2):
    """ISC OAuth2 authentication backend"""

    name = "isc-oauth2"
    REDIRECT_STATE = False
    AUTHORIZATION_URL = "https://login.intersystems.com/uat/oauth2/authorize"
    ACCESS_TOKEN_URL = "https://login.intersystems.com/uat/oauth2/token"
    ACCESS_TOKEN_METHOD = "POST"
    REVOKE_TOKEN_URL = "https://login.intersystems.com/uat/oauth2/revocation"
    REVOKE_TOKEN_METHOD = "GET"
    # The order of the default scope is important
    DEFAULT_SCOPE = ["openid", "email", "profile"]
    EXTRA_DATA = [
        ("email", "email"),
        ("username", "username"),
        ("fullname", "fullname"),
        ("refresh_token", "refresh_token", True),
        ("expires_in", "expires"),
        ("token_type", "token_type", True),
    ]

    def do_auth(self, token, *args, **kwargs):
        client_id, secret = self.get_key_and_secret()
        try:  # Decode the token, using the Application Signature from settings
            decoded = jwt.decode(token, self.get_isc_public_key(), audience=client_id)
        except jwt.DecodeError:  # Wrong signature, fail authentication
            raise AuthCanceled(self)
        data = self.user_data(token, *args, **kwargs)
        kwargs.update(
            {"response": {"token": decoded, "user_data": data}, "backend": self}
        )
        return self.strategy.authenticate(*args, **kwargs)
