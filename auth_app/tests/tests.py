from rest_framework.test import APITestCase
from django.urls import reverse
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

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


class CookieRefreshTests(APITestCase):
    def setUp(self):
        self.url = reverse('token_refresh')
        self.user = User.objects.create_user(
            username="user@example.com",
            email='user@example.com',
            password='securepassword',
        )
        # Creates a JTW refresh token for the current user
        self.refresh = RefreshToken.for_user(self.user)

    def test_cookie_refresh_no_token(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_cookie_refresh_invalid_token(self):
        # Set an invalid refresh token in the cookie so the view can read it
        self.client.cookies['refresh_token'] = 'this_is_an_invalid_token'
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_cookie_refresh_with_token(self):
        self.client.cookies['refresh_token'] = str(self.refresh)
        response = self.client.post(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.cookies)


class LogoutTests(APITestCase):
    def setUp(self):
        self.url = reverse('logout')
        self.user = User.objects.create_user(
            username="user@example.com",
            email='user@example.com',
            password='securepassword',
        )

        self.refresh = RefreshToken.for_user(self.user)

    def test_logout(self):
        # Set the refresh token in the cookie so the view can read it
        self.client.cookies['refresh_token'] = str(self.refresh)

        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertIn('refresh_token', response.cookies)
        cookie = response.cookies['refresh_token']
        self.assertEqual(cookie.value, '')
        # Check that the cookie is marked for deletion ((max-age=0))
        self.assertEqual(cookie['max-age'], 0)

        outstanding_token = OutstandingToken.objects.get(
            token=str(self.refresh))
        self.assertTrue(BlacklistedToken.objects.filter(
            token=outstanding_token).exists())

    def test_logout_no_token(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    class RequestPasswordResetTests(APITestCase):
        def setUp(self):
            self.url = reverse('password_reset')
            self.user = User.objects.create_user(
                username='user@example.com',
                email='user@example.com',
                password='securepassword',
            )

        def test_request_password(self):
            data = {
                "email": "user@example.com",
            }

            response = self.client.post(self.url, data, format='json')
            self.assertIn('detail', response.data)
            self.assertEqual(response.status_code, status.HTTP_200_OK)

        def test_request_password_email_not_exist(self):
            data = {
                "email": "usernotexist@notexist.com",
            }
            response = self.client.post(self.url, data, format='json')
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    class PasswordConfirmTests(APITestCase):
        def setUp(self):
            self.url = reverse('password_confirm')
            self.user = User.objects.create_user(
                username='user@example.com',
                email='user@example.com',
                password='securepassword'
            )

        def test_password_confirm(self):
            data = {
                "new_password": "reallysecurepassword",
                "confirm_password": "reallysecurepassword"
            }

            response = self.client.post(self.url, data, format='json')
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            # Check if the password was actually set
            self.user.refresh_from_db()
            self.assertTrue(self.user.check_password('reallysecurepassword'))

        def test_password_missmatch(self):
            data = {
                "new_password": "secure",
                "confirm_password": "password"
            }

            response = self.client.post(self.url, data, format='json')
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
