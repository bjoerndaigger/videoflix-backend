from django.urls import path
from .views import VideoListView, VideoPlaylistView, VideoSegmentView

urlpatterns = [
    path('video/', VideoListView.as_view(), name="videos"),
    path('video/<int:movie_id>/<str:resolution>/index.m3u8', VideoPlaylistView.as_view(), name="video-playlist"),
    path('video/<int:movie_id>/<str:resolution>/<str:segment>/', VideoSegmentView.as_view(), name="video-segment"),
]
