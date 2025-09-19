import os
import subprocess
from video_app.models import Video
from django.conf import settings


def convert_hls(source):
    # Split the file path into base name and extension
    base, ext = os.path.splitext(source)
    # Create target file name
    target = f"{base}.m3u8"
    # FFmpeg command to convert video to hls
    cmd = f'ffmpeg -i "{source}" -codec copy -start_number 0 -hls_time 10 -hls_list_size 0 -f hls "{target}"'
    # Run the FFmpeg command
    subprocess.run(cmd, shell=True)


def create_thumbnail(video_id):
    # Get the video instance by its ID
    instance = Video.objects.get(id=video_id)
    # Get the path of the uploaded video
    video_input_path = instance.video_file.path
    # Generate a filename fot the thumbnail
    thumbnail_filename = f"thumbnail_{instance.id}.jpg"
     # Define the relative path of the thumbnail inside the MEDIA_ROOT directory
    thumbnail_rel_path = f"thumbnails/{thumbnail_filename}"
    # Combine MEDIA_ROOT with the relative path to get the absolute output path
    thumbnail_output_path = os.path.join(settings.MEDIA_ROOT, thumbnail_rel_path)
    # Creates the directory for the thumbnail (if it doesnt exist)
    os.makedirs(os.path.dirname(thumbnail_output_path), exist_ok=True)
    # Build the FFmpeg command as a single string
    cmd = f'ffmpeg -i "{video_input_path}" -ss 00:00:01.000 -vframes 1 "{thumbnail_output_path}"'
    # Run the command in the shell
    subprocess.run(cmd, shell=True, check=True)
    # Update the thumbnail_url field with the new path
    instance.thumbnail_url.name = thumbnail_rel_path
    # Save the field to the database
    instance.save(update_fields=['thumbnail_url'])


def convert_480p(source):
    # Split the file path into base name and extension
    base, ext = os.path.splitext(source)
    # Create target file name
    target = f"{base}_480{ext}"
    # FFmpeg command to convert video to 480p
    cmd = 'ffmpeg -i "{}" -s hd480 -c:v libx264 -crf 23 -c:a aac -strict -2 "{}"'.format(source, target)
    # Run the FFmpeg command
    subprocess.run(cmd, shell=True)
