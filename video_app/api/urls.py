from django.urls import path
from .views import VideoListView

urlpatterns = [
    path('video/', VideoListView.as_view(), name="videos")
]
