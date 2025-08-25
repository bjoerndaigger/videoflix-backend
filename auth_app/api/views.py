from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from .serializers import RegisterSerializer, LoginSerializer, ResetPasswordRequestSerializer, PasswordConfirmSerializer
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail, BadHeaderError
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


def send_confirmation_mail(saved_account, activation_link):
    subject = 'Confirm your email'
    message = f'Hey {saved_account.username}, please activate your account here: {activation_link}'
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient = saved_account.email

    if subject and message and from_email:
        try:
            send_mail(
                subject,
                message,
                from_email,
                [recipient],
            )
        except BadHeaderError:
            # Raise error here; view will handle the response
            raise ValueError('Invalid header found.')
    else:
        raise ValueError('Make sure all fields are entered and valid.')


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
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

            # activation_link = f"http://localhost:5500/api/activate/{uid}/{token}/"

            # Activation link pointing to the backend API for testing (no frontend yet)
            activation_link = f'http://localhost:8000/api/activate/{uid}/{token}/'

            try:
                # Send a confirmation email with the activation link
                send_confirmation_mail(saved_account, activation_link)
            except ValueError as error:
                return Response({'error': str(error)}, status=status.HTTP_400_BAD_REQUEST)

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


def send_reset_password_mail(user, reset_link):
    subject = 'Reset your password'
    message = f'Hey {user.username}, please reset your password here: {reset_link}'
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient = user.email

    if subject and message and from_email:
        try:
            send_mail(
                subject,
                message,
                from_email,
                [recipient],
            )
        except BadHeaderError:
            raise ValueError('Invalid header found.')
    else:
        raise ValueError('Make sure all fields are entered and valid.')


class RequestPasswordResetView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = ResetPasswordRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']

            try:
                user = User.objects.get(email=email)
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))

                # reset_link = f"http://localhost:5500/api/password_confirm/{uid}/{token}/"

                # Reset link pointing to the backend API for testing (no frontend yet)
                reset_link = f'http://localhost:8000/api/password_confirm/{uid}/{token}/'
                try:
                    send_reset_password_mail(user, reset_link)
                except ValueError as error:
                    return Response({'error': str(error)}, status=status.HTTP_400_BAD_REQUEST)

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
