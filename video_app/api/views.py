from rest_framework.generics import ListAPIView
from video_app.models import Video
from .serializers import VideoSerializer
from rest_framework.permissions import IsAuthenticated


class VideoListView(ListAPIView):
    queryset = Video.objects.all()

    serializer_class = VideoSerializer
    

