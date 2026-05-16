from django.urls import path
from . import views

urlpatterns = [
    path('ingest/', views.ingest_event, name='ingest_event'),
    path('events/', views.list_events, name='list_events'),
]
