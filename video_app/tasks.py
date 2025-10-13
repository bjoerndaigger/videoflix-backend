import os
import subprocess
from video_app.models import Video
from django.conf import settings


def convert_hls(source, movie_id, resolution):
    """
    Converts a video file into HLS (HTTP Live Streaming) format for a specific resolution.

    Uses FFmpeg to transcode the input video into .ts segments and generates
    an HLS playlist (index.m3u8) in a dedicated folder for the given resolution.

    Args:
        source (str): Absolute path to the input video file.
        movie_id (int | str): Unique ID of the video/movie.
        resolution (str): Desired output resolution ('480p', '720p', '1080p').

    Returns:
        str: The path to the generated HLS playlist file (index.m3u8).

    Raises:
        KeyError: If an unsupported resolution is passed.
        subprocess.CalledProcessError: If the FFmpeg command fails.
    """
    target_dir = f"media/video/{movie_id}/{resolution}"

    os.makedirs(target_dir, exist_ok=True)

    target = os.path.join(target_dir, "index.m3u8")

    resolutions = {
        "480p": "854:480",
        "720p": "1280:720",
        "1080p": "1920:1080"
    }

    scale = resolutions.get(resolution)

    cmd = f'ffmpeg -i "{source}" -vf "scale={scale}" -c:v libx264 -crf 23 -preset veryfast -c:a aac -b:a 128k -start_number 0 -hls_time 10 -hls_list_size 0 -f hls "{target}"'

    subprocess.run(cmd, shell=True)

    return target


def create_thumbnail(video_id):
    """
    Generates a thumbnail image from a video and updates the Video instance.

    Extracts a single frame at 1 second from the video using FFmpeg, saves it
    under MEDIA_ROOT/thumbnails, and updates the `thumbnail_url` field.

    Args:
        video_id (int): Primary key of the Video instance.

    Raises:
        Video.DoesNotExist: If no Video exists with the given ID.
        subprocess.CalledProcessError: If the FFmpeg command fails.
    """
    instance = Video.objects.get(id=video_id)
    video_input_path = instance.video_file.path

    thumbnail_filename = f"thumbnail_{instance.id}.jpg"
    thumbnail_rel_path = f"thumbnails/{thumbnail_filename}"
    thumbnail_output_path = os.path.join(
        settings.MEDIA_ROOT, thumbnail_rel_path)

    os.makedirs(os.path.dirname(thumbnail_output_path), exist_ok=True)

    cmd = f'ffmpeg -i "{video_input_path}" -ss 00:00:01.000 -vframes 1 "{thumbnail_output_path}"'
    subprocess.run(cmd, shell=True, check=True)

    instance.thumbnail_url.name = thumbnail_rel_path
    instance.save(update_fields=['thumbnail_url'])
