from rest_framework import serializers
from video_app.models import Video


class VideoSerializer(serializers.ModelSerializer):
    """
    Serializer for the Video model.

    Converts `Video` model instances to JSON and validates
    incoming data for creating or updating video objects.

    Attributes:
        created_at (DateTimeField): Read-only timestamp of video creation,
            formatted in ISO 8601 (`YYYY-MM-DDTHH:MM:SSZ`).
    """
    created_at = serializers.DateTimeField(
        format="%Y-%m-%dT%H:%M:%SZ", read_only=True)

    class Meta:
        """
        Meta configuration for the VideoSerializer.

        Attributes:
            model (Model): The Django model associated with this serializer (`Video`).
            fields (list): The model fields to include in the serialized output.
        """
        model = Video
        fields = ['id', 'created_at', 'title', 'description', 'thumbnail_url', 'category']
