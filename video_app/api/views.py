from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from video_app.models import Video
from .serializers import VideoSerializer
from rest_framework.response import Response
from django.http import FileResponse
import os
from django.conf import settings


class VideoListView(ListAPIView):
    """
    API endpoint to list all available videos.

    Provides a read-only list of all `Video` objects stored in the database.
    Inherits from Django REST Framework's `ListAPIView`, which handles GET requests
    and automatically serializes queryset data.

    Attributes:
        queryset (QuerySet): The set of all `Video` instances to be listed.
        serializer_class (Serializer): The serializer used to format the video data.
    """
    queryset = Video.objects.all()

    serializer_class = VideoSerializer


class VideoPlaylistView(APIView):
    """
    API endpoint to serve an HLS (HTTP Live Streaming) playlist file (.m3u8).

    This view dynamically constructs the file path to a movie's playlist based
    on its `movie_id` and desired `resolution`. If the file exists, it returns
    it as a streamable HLS response. Otherwise, it returns a 404 error.
    """

    def get(self, request, movie_id, resolution):
        """
        Handles GET requests to retrieve an HLS playlist.

        Args:
            request (Request): The incoming HTTP request object.
            movie_id (int | str): The unique ID of the movie.
            resolution (str): The desired video resolution (e.g., '720p', '1080p').

        Returns:
            FileResponse: The `.m3u8` playlist file if it exists.
            Response: A 404 JSON response if the file is not found.
        """
        file_path = os.path.join(
            settings.MEDIA_ROOT,
            "video",
            str(movie_id),
            resolution,
            "index.m3u8"
        )

        if os.path.exists(file_path):
            return FileResponse(
                open(file_path, 'rb'),
                content_type='application/vnd.apple.mpegurl'
            )

        return Response({"error": "Playlist not found"}, status=404)


class VideoSegmentView(APIView):
    """
    API endpoint to serve individual HLS video segments (.ts files).

    Each segment represents a small part of the video file and is requested
    sequentially by video players (like HTML5 or HLS.js) when streaming content.

    Example URL:
        GET /api/video/<movie_id>/<resolution>/<segment>/

    Example:
        /api/video/42/1080p/segment3.ts
    """

    def get(self, request, movie_id, resolution, segment):
        """
        Handles GET requests to serve a specific HLS video segment.

        Args:
            request (Request): The incoming HTTP request object.
            movie_id (int | str): The unique movie ID.
            resolution (str): The video resolution folder.
            segment (str): The filename of the segment (e.g., 'segment1.ts').

        Returns:
            FileResponse: The requested `.ts` segment file if found.
            Response: A 404 JSON response if the file does not exist.
        """
        file_path = os.path.join(
            settings.MEDIA_ROOT,
            "video",
            str(movie_id),
            resolution,
            segment
        )

        if os.path.exists(file_path):
            return FileResponse(
                open(file_path, 'rb'),
                content_type='video/MP2T'
            )

        return Response({"error": "Segment not found"}, status=404)
