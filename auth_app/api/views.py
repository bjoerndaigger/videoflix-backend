from auth_app.tasks import send_confirmation_mail, send_reset_password_mail
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from .serializers import RegisterSerializer, LoginSerializer, ResetPasswordRequestSerializer, PasswordConfirmSerializer
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
import django_rq


User = get_user_model()


class RegisterView(APIView):
    """
    A view for handling user registration.

    This view allows new users to create an account. Anyone (including
    unauthenticated users) can access this endpoint to register.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Handles POST requests to create a new user account.

        Validates the submitted user data using the `RegisterSerializer`.
        If the data is valid:
        1. A new user is saved to the database (but marked as inactive).
        2. A unique, time-sensitive activation token and a UID are generated.
        3. An activation link is created.
        4. A confirmation email is sent asynchronously via an RQ (Redis Queue)
           to avoid blocking the application.
        5. The new user's data is returned.

        Args:
            request (Request): The Django REST Framework request object, containing
                               user data (e.g., email, password) in its body.

        Returns:
            Response: An HTTP response.
                - On success (Status 201 CREATED): A JSON object with the user's
                  data ('id', 'email') and the generated token.
                - On failure (Status 400 BAD_REQUEST): A JSON object with the
                  serializer's validation errors.
        """
        serializer = RegisterSerializer(data=request.data)

        data = {}
        if serializer.is_valid():
            saved_account = serializer.save()

            # default_token_generator is an instance of PasswordResetTokenGenerator
            # make_token() creates a secure, time-sensitive token for the user
            # Token can later be verified with check_token()
            token = default_token_generator.make_token(saved_account)
            # Encode the user's ID into a URL-safe string for the activation link
            uid = urlsafe_base64_encode(force_bytes(saved_account.pk))

            activation_link = f"http://localhost:5500/pages/auth/activate.html?uid={uid}&token={token}"

            queue = django_rq.get_queue('default')

            # Send a confirmation email with the activation link
            queue.enqueue(send_confirmation_mail,
                          saved_account, activation_link)

            # Build the response data to return to the client
            data = {
                'user': {
                    'id': saved_account.id,
                    'email': saved_account.email,
                },
                'token': token
            }

            return Response(data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ActivateAccountView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, uidb64, token):
        try:
            # Convert the user ID from the URL back to a string
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, User.DoesNotExist):
            raise ValidationError('Invalid or expired activation link.')

        # Verify the token with check_token
        if user is not None and default_token_generator.check_token(user, token):
            # Activate the user account
            user.is_active = True
            user.save()
            return Response({'message': 'Account successfully activated.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid link.'}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        # Initialize the serializer with the incoming request data (email & password)
        serializer = self.get_serializer(data=request.data)
        try:
            # Automatically returns errors if validation fails
            serializer.is_valid(raise_exception=True)
        except ValidationError:
            return Response(
                {'detail': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Extract the JWT tokens from the validated data
        refresh = serializer.validated_data["refresh"]
        access = serializer.validated_data["access"]

        user = User.objects.get(email=request.data["email"])
        response = Response({
            'detail': 'Login succesful',
            'user': {
                'id': user.pk,
                'email': user.email,
            },
        }, status=status.HTTP_200_OK)

        # Set the access token as an HttpOnly cookie
        response.set_cookie(
            key='access_token',
            value=access,
            httponly=True,
            secure=True,
            samesite='Lax'
        )

        # Set the refresh token as an HttpOnly cookie
        response.set_cookie(
            key='refresh_token',
            value=refresh,
            httponly=True,
            secure=True,
            samesite='Lax'
        )

        return response


class CookieRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get('refresh_token')

        if refresh_token is None:
            return Response({'detail': 'Refresh token not found'}, status=status.HTTP_400_BAD_REQUEST)

        # Create a serializer instance with the refresh token
        # Standard serializer from TokenRefreshView (TokenRefreshSerializer from SimpleJWT)
        serializer = self.get_serializer(data={'refresh': refresh_token})

        # Validate the token – stops the function if the token is invalid or expired
        try:
            serializer.is_valid(raise_exception=True)
        except Exception:
            return Response({'detail': 'Refresh token invalid'}, status=status.HTTP_401_UNAUTHORIZED)

        # Get a new access token
        new_access_token = serializer.validated_data.get('access')

        # Erstelle eine neue Response
        response = Response({
            'detail': 'Token refreshed',
            'access': new_access_token
        }, status=status.HTTP_200_OK)

        # Set the new access token as an HttpOnly cookie
        response.set_cookie(
            key='access_token',
            value=new_access_token,
            httponly=True,
            secure=True,
            samesite='Lax'
        )

        return response


class LogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # Retrieve the refresh token from the HttpOnly cookie
        refresh_token = request.COOKIES.get('refresh_token')

        if not refresh_token:
            return Response(
                {'error': 'No refresh token found in cookies. User may already be logged out.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            # Create a RefreshToken object from the token string
            token = RefreshToken(refresh_token)

            # Blacklist the refresh token so it cannot be used again
            token.blacklist()

            response = Response(
                {'detail': 'Logout successful! All tokens will be deleted. Refresh token is now invalid.'}, status=status.HTTP_200_OK)

            # Delete the access and refresh token cookies to remove them from the client
            response.delete_cookie('access_token')
            response.delete_cookie('refresh_token')
            return response
        except Exception as error:
            return Response({'error': str(error)}, status=status.HTTP_400_BAD_REQUEST)


class RequestPasswordResetView(APIView):
    """
    Handles the first step of the password reset process.

    This view receives a POST request with an email address. If the email
    corresponds to an existing user, it triggers an email to be sent with a
    password reset link. For security, it always returns a success response,
    regardless of whether the email exists in the database.
    """
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        """
        Initiates a password reset request for a user.

        Validates the provided email. If a user with this email exists, a password
        reset token and link are generated and sent to the user's email address
        asynchronously.

        To prevent user enumeration attacks (where an attacker could determine
        if an email is registered), this endpoint will always return a successful
        response, even if the email does not exist in the system.

        Args:
            request (Request): The request object containing the user's email.

        Returns:
            Response: An HTTP 200 OK response with a generic confirmation message.
        """
        serializer = ResetPasswordRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']

            try:
                user = User.objects.get(email=email)
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))

                reset_link = f"http://127.0.0.1:5500/pages/auth/confirm_password.html?uid={uid}&token={token}"

                queue = django_rq.get_queue('default')

                queue.enqueue(send_reset_password_mail, user, reset_link)

            except User.DoesNotExist:
                # Do nothing if the user doesn't exist to avoid revealing account info
                pass

            # Always return 200 OK for security reasons
            return Response(
                {'detail': 'An email has been sent to reset your password.'}, status=status.HTTP_200_OK
            )


class PasswordConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, User.DoesNotExist):
            raise ValidationError('Invalid or expired activation link.')

        serializer = PasswordConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if user is not None and default_token_generator.check_token(user, token):
            new_password = serializer.validated_data['new_password']
            user.set_password(new_password)
            user.save()
            return Response({'detail': 'Your Password has been successfully reset.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid or expired link.'}, status=status.HTTP_400_BAD_REQUEST)


# Protected test endpoint to verify JWT authentication
class TestProtectedView(APIView):
    def get(self, request):
        return Response({
            'detail': 'Access granted',
            'user': request.user.email
        })
