import os
import subprocess

def convert_480p(source):
     # Split the file path into base name and extension
    base, ext = os.path.splitext(source)
     # Create target file name
    target = f"{base}_480{ext}"
    # FFmpeg command to convert video to 480p
    cmd = 'ffmpeg -i "{}" -s hd480 -c:v libx264 -crf 23 -c:a aac -strict -2 "{}"'.format(source, target)
    # Run the FFmpeg command
    subprocess.run(cmd, shell=True)

