"""Custom Trino authentication method
"""
from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2.rfc6749 import OAuth2Token
from trino.auth import Authentication


class OAuth2ClientCredentialAuthentication(Authentication):
    """
    See:
    * :class:`authlib.integrations.requests_client.oauth2_session.OAuth2Auth`
    * :class:`authlib.oauth2.client.OAuth2Client`
    """

    def __init__(self, client_id: str, client_secret: str, token_endpoint: str, **kwargs) -> None:
        self.client = OAuth2Session(
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint_auth_method=token_endpoint,
            **kwargs,
        )

    def set_http_session(self, http_session):
        self.fetch_token()
        http_session.auth = self.client.token_auth
        return http_session

    def fetch_token(self):
        token: OAuth2Token = self.client.token
        if not token or token.is_expired() is True:
            self.client.token = self.client.fetch_access_token(grant_type="client_credentials")
