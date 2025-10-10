from rest_framework_simplejwt.authentication import JWTAuthentication


class CookieJWTAuthentication(JWTAuthentication):
    """
    Custom JWT authentication class that supports HttpOnly cookie authentication.

    Extends the default `JWTAuthentication` class from SimpleJWT to allow
    retrieving the access token from a cookie named `access_token` in addition
    to the standard Authorization header.

    Methods:
        authenticate(request): Attempts to authenticate the user using the cookie.
    """

    def authenticate(self, request):
        """
        Authenticates the user using the `access_token` cookie.

        This method first looks for the JWT access token in the request cookies.
        If the token exists, it validates it using SimpleJWT's standard logic.
        Upon successful validation, it returns the associated user and the
        validated token.

        Args:
            request (Request): The Django REST Framework request object.

        Returns:
            tuple: (user, validated_token) if authentication succeeds.
            None: If no access token is found in cookies.

        Raises:
            AuthenticationFailed: If the token is invalid or expired (handled
                                  internally by SimpleJWT).
        """
        access_token = request.COOKIES.get("access_token")

        if not access_token:
            return None

        validated_token = self.get_validated_token(access_token)
        return self.get_user(validated_token), validated_token
