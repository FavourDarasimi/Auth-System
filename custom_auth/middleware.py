from rest_framework_simplejwt.authentication import JWTAuthentication

from rest_framework_simplejwt.exceptions import (
    AuthenticationFailed
)

from .utils import is_blacklisted


class BlacklistMiddleware(JWTAuthentication):

    def authenticate(self, request):

        result = super().authenticate(request)

        if result is None:
            return None

        user, token = result

        jti = token.get("jti")

        if is_blacklisted(jti):
            raise AuthenticationFailed(
                "Token revoked"
            )

        return (user, token)