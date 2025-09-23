from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from video_app.models import Video
from .serializers import VideoSerializer
from rest_framework.response import Response
from django.http import FileResponse
import os
from django.conf import settings


class VideoListView(ListAPIView):
    queryset = Video.objects.all()

    serializer_class = VideoSerializer


class VideoPlaylistView(APIView):
    def get(self, request, movie_id, resolution):
        # Build the absolute path to the HLS playlist
        file_path = os.path.join(
            settings.MEDIA_ROOT,  # /app/media in Docker
            "video",
            str(movie_id),
            resolution,
            "index.m3u8"
        )

        # Check if the playlist exists
        if os.path.exists(file_path):
            # Serve the playlist so the browser/player can play it as HLS
            return FileResponse(
                open(file_path, 'rb'),
                content_type='application/vnd.apple.mpegurl'
            )

        # Return 404 if the playlist is not found
        return Response({"error": "Playlist not found"}, status=404)


class VideoSegmentView(APIView):
    # GET /api/video/<movie_id>/<resolution>/<segment>/
    # Returns a single HLS video segment (.ts) for the specified movie and resolution.
    def get(self, request, movie_id, resolution, segment):
        # Build absolute path to the .ts segment
        file_path = os.path.join(
            settings.MEDIA_ROOT,
            "video",
            str(movie_id),
            resolution,
            segment
        )

        # Check if the segment exists
        if os.path.exists(file_path):
            return FileResponse(
                open(file_path, 'rb'),
                content_type='video/MP2T'
            )

        # Return 404 if the segment is not found
        return Response({"error": "Segment not found"}, status=404)
