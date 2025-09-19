from rest_framework import serializers
from video_app.models import Video


class VideoSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(
        format="%Y-%m-%dT%H:%M:%SZ", read_only=True)

    class Meta:
        model = Video
        fields = '__all__'
