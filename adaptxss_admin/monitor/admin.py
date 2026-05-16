from django.contrib import admin
from .models import XSSEvent

@admin.register(XSSEvent)
class XSSEventAdmin(admin.ModelAdmin):
    list_display  = ('session_id', 'label', 'probability', 'latency_ms', 'created_at')
    list_filter   = ('label',)
    search_fields = ('session_id',)
    readonly_fields = ('features',)
    ordering = ('-created_at',)
