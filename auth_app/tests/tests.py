from rest_framework.test import APITestCase
from django.urls import reverse
from rest_framework import status
from django.contrib.auth.models import User


class RegisterTests(APITestCase):
    def setUp(self):
        self.url = reverse('register')
        self.data = {
            "email": "user@example.com",
            "password": "securepassword",
            "confirmed_password": "securepassword"
        }
    
    def test_register(self):
        response = self.client.post(self.url, self.data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(email="user@example.com")
        self.assertEqual(user.email, "user@example.com")