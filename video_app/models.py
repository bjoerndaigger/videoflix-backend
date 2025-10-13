from django.db import models


class Video(models.Model):
    """
    Represents a video uploaded to the platform.

    Attributes:
        created_at (DateTimeField): Timestamp of when the video was created.
        title (CharField): The title of the video. Defaults to "Untitled".
        description (TextField): Description of the video. Defaults to "No description".
        thumbnail_url (FileField): Optional thumbnail image for the video.
        video_file (FileField): The actual video file.
        category (CharField): The category of the video (Entertainment, Education, Nature, Other).
    """
    class Category(models.TextChoices):
        """
        Defines the available categories for videos as human-readable choices.

        Choices:
            ENTERTAINMENT: Entertainment content
            EDUCATION: Educational content
            NATURE: Nature-related content
            OTHER: Any other type of content
        """
        ENTERTAINMENT = "entertainment", "Entertainment"
        EDUCATION = "education", "Education"
        NATURE = "nature", "Nature"
        OTHER = "other", "Other"

    created_at = models.DateTimeField(auto_now_add=True)
    title = models.CharField(max_length=255, default="Untitled")
    description = models.TextField(default="No description")
    thumbnail_url = models.FileField(
        upload_to='thumbnails', blank=True, null=True)
    video_file = models.FileField(upload_to='video')

    category = models.CharField(
        max_length=20, choices=Category, default=Category.OTHER)

    def __str__(self):
        """
        Returns a human-readable string representation of the video.

        Returns:
            str: The title of the video.
        """
        return self.title
