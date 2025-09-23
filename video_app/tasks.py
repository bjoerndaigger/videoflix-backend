import os
import subprocess
from video_app.models import Video
from django.conf import settings


def convert_hls(source, movie_id, resolution):
    # Set the folder where the HLS files will be saved
    target_dir = f"media/video/{movie_id}/{resolution}"

    # Create the folder if it does not exist
    os.makedirs(target_dir, exist_ok=True)

    # Path to HLS Playlist
    target = os.path.join(target_dir, "index.m3u8")

    # Use the input parameter 'resolution' to pick the correct size
    resolutions = {
        "480p": "854:480",
        "720p": "1280:720",
        "1080p": "1920:1080"
    }

     # Get the pixel size for the requested resolution
    scale = resolutions.get(resolution)

    # Build the ffmpeg command to convert the video to HLS format
    cmd = f'ffmpeg -i "{source}" -vf "scale={scale}" -c:v libx264 -crf 23 -preset veryfast -c:a aac -b:a 128k -start_number 0 -hls_time 10 -hls_list_size 0 -f hls "{target}"'
    
    # Run the command in the shell
    subprocess.run(cmd, shell=True)
    
    # Return the path to the HLS playlist
    return target


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
