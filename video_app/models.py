from django.db import models

# Create your models here.


class Video(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    title = models.CharField(max_length=255)
    description = models.TextField()
    thumbnail_url = models.FileField(upload_to='thumbnails')
    video_file = models.FileField(upload_to='video')
    category = models.CharField(max_length=100)
