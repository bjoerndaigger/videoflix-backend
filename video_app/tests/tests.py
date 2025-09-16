from rest_framework.test import APITestCase
from django.urls import reverse
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from video_app.models import Video
from django.core.files.uploadedfile import SimpleUploadedFile


class VideoViewTests(APITestCase):
    def setUp(self):
        self.videos_url = reverse('videos')
        self.login_url = reverse('login')

        self.user = User.objects.create_user(
            username='user@example.com',
            email='user@example.com',
            password='securepassword',
        )

        # Create dummy video and thumbail
        self.video_file = SimpleUploadedFile(
            "video.mp4", b"file_content", content_type="video/mp4"
        )
        self.thumbnail = SimpleUploadedFile(
            "thumbnail.jpg", b"file_content", content_type="image/jpeg"
        )

        # Create a video in the database
        self.video = Video.objects.create(
            title="Test Video",
            description="Test description",
            thumbnail_url=self.thumbnail,
            video_file=self.video_file,
            category=Video.Category.EDUCATION,
        )

    def test_videolist(self):
        # Authenticate user
        data = {
            "email": "user@example.com",
            "password": "securepassword"
        }

        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Checks if the API returns a video with correct data 
        response = self.client.get(self.videos_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        video_data = response.data[0]
        self.assertEqual(video_data['title'], 'Test Video')
        self.assertEqual(video_data['description'], 'Test description')
        self.assertEqual(video_data['category'], Video.Category.EDUCATION)
        self.assertIn('created_at', video_data)  
        self.assertIn('thumbnail_url', video_data)  

     
    
