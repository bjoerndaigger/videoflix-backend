from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
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
        if attrs['password'] != attrs['confirmed_password']:
            raise serializers.ValidationError('Passwords do not match.')
        return attrs

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('Email already exists.')
        return value

    def save(self):
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
    # Define the fields we expect in the login request
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def __init__(self, *args, **kwargs):
        # Call parent constructor to initialize default fields ('username', 'password')
        super().__init__(*args, **kwargs)

        # Remove 'username' field (default from TokenObtainPairSerializer), because we want to authenticate using 'email' instead
        if 'username' in self.fields:
            self.fields.pop('username')

    def validate(self, attrs):
        # Extract the email and password values from the request data
        email = attrs.get('email')
        password = attrs.get('password')

        # Try to find a user with the given email
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError('Invalid email or password')

        # Check if the provided password matches the stored password
        if not user.check_password(password):
            raise serializers.ValidationError('Invalid email or password')

       # Re-add 'username' for the parent serializer, which needs it to authenticate and create JWT tokens
        attrs['username'] = user.username

        # Generate refresh + access tokens using parent serializer
        data = super().validate(attrs)

        return data


class ResetPasswordRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
