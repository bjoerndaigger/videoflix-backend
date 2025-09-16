from video_app.models import Video
from django.dispatch import receiver
from django.db.models.signals import post_save, post_delete
import os

# @receiver decorator connects the video_post_save function to the post_save signal
@receiver(post_save, sender=Video)
# Triggered every time a video instance is created or updated
def video_post_save(sender, instance, created, **kwargs):
    print('Video saved')
    if created:
        # Runs only when a new video instance is created
        print('New video created')

@receiver(post_delete, sender=Video)
def auto_delete_file_on_delete(sender, instance, **kwargs):
    # Deletes file from filesystem wehen corresponding video object is deleted
    if instance.video_file:
        if os.path.isfile(instance.video_file.path):
            os.remove(instance.video_file.path)
            print('Video deleted')
