from django.db import models


class Video(models.Model):
    class Category(models.TextChoices):
        ENTERTAINMENT = "ent", "Entertainment"
        EDUCATION = "edu", "Education"
        NATURE = "nat", "Nature"
        OTHER = "oth", "Other"

    created_at = models.DateTimeField(auto_now_add=True)
    title = models.CharField(max_length=255, default="Untitled")
    description = models.TextField(default="No description")
    thumbnail_url = models.FileField(upload_to='thumbnails', blank=True, null=True)
    video_file = models.FileField(upload_to='video')

    category = models.CharField(
        max_length=20, choices=Category, default=Category.OTHER)

    def __str__(self):
        return self.title
