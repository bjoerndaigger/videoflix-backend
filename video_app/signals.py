from video_app.models import Video
from django.dispatch import receiver
from django.db.models.signals import post_save, post_delete
import os, glob, django_rq
from video_app.tasks import convert_480p, convert_hls, create_thumbnail



# @receiver decorator connects the video_post_save function to the post_save signal
@receiver(post_save, sender=Video)
# Triggered every time a video instance is created or updated
def video_post_save(sender, instance, created, **kwargs):
    print('Video saved')
    if created:
        # Runs only when a new video instance is created
        print('New video created')

        # Get the default RQ queue (autocommit=True ensures the job is added immediately)
        queue = django_rq.get_queue('default', autocommit=True)
        # Converts the uploaded video to 480p as a background job
        queue.enqueue(convert_480p, instance.video_file.path)
        # Converts the uploaded video to hls as a background job
        queue.enqueue(convert_hls, instance.video_file.path)
        # Create thumbnail
        queue.enqueue(create_thumbnail, instance.id)


@receiver(post_delete, sender=Video)
def auto_delete_file_on_delete(sender, instance, **kwargs):
    # Deletes file from filesystem wehen corresponding video object is deleted
    if instance.video_file:
        if os.path.isfile(instance.video_file.path):
            os.remove(instance.video_file.path)
            print('Video deleted')

         # Delete the hls playlist if it exists
        base, ext = os.path.splitext(instance.video_file.path)
        path_hls = f"{base}.m3u8"
        if os.path.isfile(path_hls):
            os.remove(path_hls)
            print('HLS-version deleted')

        # Delete all .ts segments
        # glob is used to find all matching files by specific pattern in the same folder
        ts_files = glob.glob(f"{base}*.ts")
        for ts_file in ts_files:
            os.remove(ts_file)

        # Delete the 480p version if it exists
        base, ext = os.path.splitext(instance.video_file.path)
        path_480p = f"{base}_480{ext}"
        if os.path.isfile(path_480p):
            os.remove(path_480p)
            print('480p-version deleted')

        # Delete thumbnail
        if os.path.isfile(instance.thumbnail_url.path):
            os.remove(instance.thumbnail_url.path)
            print('Thumbnail deleted')
