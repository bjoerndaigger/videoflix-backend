from rest_framework.test import APITestCase
from django.urls import reverse
from rest_framework import status
from django.contrib.auth.models import User
# from django.contrib.auth.models import User
from django.contrib.auth import get_user_model # Use the current User Model and not the Standard Model

User = get_user_model()


class RegisterTests(APITestCase):
    def setUp(self):
        self.url = reverse('register')
        self.data = {
            "email": "user@example.com",
            "password": "securepassword",
            "confirmed_password": "securepassword"
        }

    def test_register(self):
        response = self.client.post(self.url, self.data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(email='user@example.com')

        self.assertEqual(user.email, 'user@example.com')
        self.assertTrue(user.check_password('securepassword'))

        # Checks if Account is inactive
        self.assertFalse(user.is_active)


class LoginTests(APITestCase):
    def setUp(self):
        self.url = reverse('login')
        self.user = User.objects.create_user(
            username='user@example.com',
            email='user@example.com',
            password='securepassword',
            is_active=True
        )

    def test_login(self):
        data = {
            "email": "user@example.com",
            "password": "securepassword"
        }

        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['detail'], 'Login succesful')
        self.assertEqual(response.data['user']['email'], 'user@example.com')

        # Check that access and refresh tokens are set as cookies
        self.assertIn('access_token', response.cookies)
        self.assertIn('refresh_token', response.cookies)

    def test_login_fail_wrong_password(self):
        data = {
            "email": "user@example.com",
            "password": "wrongpassword"
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_fail_nonexistent_user(self):
        data = {
            "email": "nonexistent@example.com",
            "password": "any_password"
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
