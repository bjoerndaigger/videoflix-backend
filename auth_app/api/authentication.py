from rest_framework_simplejwt.authentication import JWTAuthentication

# Standard JWTAuthentication class only checks the authorization header for a bearer token
# This class extends JWTAuthentication to also allow authentication via HttpOnly cookies
class CookieJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # Try to retrieve the access token from the request cookies
        access_token = request.COOKIES.get("access_token")

        if not access_token:
            return None
        
        # Validate the token using SimpleJWT's built-in validation logic
        validated_token = self.get_validated_token(access_token)

        # Return the user associated with the token and the validated token itself
        return self.get_user(validated_token), validated_token
