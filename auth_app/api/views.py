from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from .serializers import RegisterSerializer
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail, BadHeaderError
from django.conf import settings


def send_confirmation_mail(saved_account, activation_link):
    subject = "Confirm your email"
    message = f"Hey {saved_account.username}, please activate your account here: {activation_link}"
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
            raise ValueError("Invalid header found.")
    else:
        raise ValueError("Make sure all fields are entered and valid.")


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)

        data = {}
        if serializer.is_valid():
            saved_account = serializer.save()

            token = default_token_generator.make_token(saved_account)
            uid = urlsafe_base64_encode(force_bytes(saved_account.pk))

            activation_link = f"http://localhost:5500/api/activate/{uid}/{token}/"

            try:
                # Send a confirmation email with the activation link
                send_confirmation_mail(saved_account, activation_link)
            except ValueError as error:
                return Response({"detail": str(error)}, status=status.HTTP_400_BAD_REQUEST)

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
