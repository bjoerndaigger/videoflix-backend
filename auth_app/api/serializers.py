from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for registering a new user.

    Handles validation for password confirmation and unique email,
    and creates a new inactive user account for email verification.
    """
    confirmed_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'confirmed_password']
        extra_kwargs = {
            'password': {
                'write_only': True
            },
            'email': {
                'required': True
            }
        }

    def validate(self, attrs):
        """
        Ensure that password and confirmed_password match.

        Args:
            attrs (dict): The incoming serializer data.

        Returns:
            dict: Validated attributes.

        Raises:
            ValidationError: If passwords do not match.
        """
        if attrs['password'] != attrs['confirmed_password']:
            raise serializers.ValidationError('Passwords do not match.')
        return attrs

    def validate_email(self, value):
        """
        Ensure the email is unique in the system.

        Args:
            value (str): The email to validate.

        Returns:
            str: The validated email.

        Raises:
            ValidationError: If the email already exists.
        """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('Email already exists.')
        return value

    def save(self):
        """
        Creates a new user account with the provided email and password.

        The account is inactive by default, requiring email confirmation.

        Returns:
            User: The newly created user instance.
        """
        password = self.validated_data['password']
        email = self.validated_data['email']
        account = User(
            email=email,
            username=email
        )
        account.set_password(password)
        # Set account inactive by default (requires email confirmation)
        account.is_active = False
        account.save()
        return account


class LoginSerializer(TokenObtainPairSerializer):
    """
    Serializer for user login using email and password.

    Extends SimpleJWT's TokenObtainPairSerializer to allow login via email
    instead of username.
    """
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def __init__(self, *args, **kwargs):
        """
        Remove the default 'username' field from the parent serializer
        because authentication is done via email.
        """
        super().__init__(*args, **kwargs)
        if 'username' in self.fields:
            self.fields.pop('username')

    def validate(self, attrs):
        """
        Validate user credentials and generate JWT tokens.

        Args:
            attrs (dict): Contains 'email' and 'password'.

        Returns:
            dict: JWT token pair (access and refresh).

        Raises:
            ValidationError: If email or password is incorrect.
        """
        email = attrs.get('email')
        password = attrs.get('password')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError('Invalid email or password')

        if not user.check_password(password):
            raise serializers.ValidationError('Invalid email or password')

        # Add username for parent serializer to generate tokens
        attrs['username'] = user.username
        data = super().validate(attrs)
        return data


class ResetPasswordRequestSerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset.

    Only requires a valid email address.
    """
    email = serializers.EmailField(required=True)


class PasswordConfirmSerializer(serializers.Serializer):
    """
    Serializer for confirming a new password during reset.

    Ensures new_password and confirm_password match.
    """
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        """
        Check that the new password and confirmation match.

        Args:
            attrs (dict): Contains 'new_password' and 'confirm_password'.

        Returns:
            dict: Validated attributes.

        Raises:
            ValidationError: If passwords do not match.
        """
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError('Passwords do not match.')
        return attrs
