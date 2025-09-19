from django.contrib import admin
from .models import Video

# Register your models here.


class VideoAdmin(admin.ModelAdmin):
    readonly_fields = ('thumbnail_url', 'created_at')


admin.site.register(Video, VideoAdmin)
