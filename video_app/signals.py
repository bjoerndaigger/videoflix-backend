from video_app.models import Video
from django.dispatch import receiver
from django.db.models.signals import post_save, post_delete
import os
import django_rq
from video_app.tasks import convert_hls, create_thumbnail
from django.conf import settings
import shutil


@receiver(post_save, sender=Video)
def video_post_save(sender, instance, created, **kwargs):
    """
    Handles post-save operations for a Video instance.

    This signal handler is triggered after a Video model is saved.
    If a new video instance is created, it enqueues background tasks
    to process the video into different HLS resolutions (480p, 720p, 1080p)
    and to generate a thumbnail.

    Args:
        sender (Model): The model class that sent the signal (Video).
        instance (Video): The actual instance being saved.
        created (bool): A boolean; True if a new record was created.
        **kwargs: Wildcard keyword arguments.
    """
    if created:
        # Get the default RQ queue
        queue = django_rq.get_queue('default', autocommit=True)

        # Enqueue tasks to convert the video to HLS format in multiple resolutions
        queue.enqueue(convert_hls, instance.video_file.path,
                      instance.id, '480p')
        queue.enqueue(convert_hls, instance.video_file.path,
                      instance.id, '720p')
        queue.enqueue(convert_hls, instance.video_file.path,
                      instance.id, '1080p')

        # Enqueue a task to create a thumbnail for the video
        queue.enqueue(create_thumbnail, instance.id)


@receiver(post_delete, sender=Video)
def auto_delete_file_on_delete(sender, instance, **kwargs):
    """
    Cleans up associated files and directories when a Video instance is deleted.

    This signal handler is triggered after a Video model is deleted. It ensures
    that the original video file, the thumbnail, and the entire directory
    containing HLS files are removed from the filesystem to prevent orphaned files.

    Args:
        sender (Model): The model class that sent the signal (Video).
        instance (Video): The instance that was deleted.
        **kwargs: Wildcard keyword arguments.
    """
    # Delete the original video file if it exists
    if instance.video_file:
        instance.video_file.delete(save=False)

    # Delete the thumbnail file if it exists
    if instance.thumbnail_url:
        instance.thumbnail_url.delete(save=False)

    # Construct the path to the directory containing HLS files
    hls_directory = os.path.join(
        settings.MEDIA_ROOT, 'video', str(instance.id))

    # If the directory exists, remove it and all its contents
    if os.path.isdir(hls_directory):
        shutil.rmtree(hls_directory)
