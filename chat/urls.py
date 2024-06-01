# chat/urls.py
from django.urls import path

from . import views

urlpatterns = [
    path('', views.chatting, name='chatting'),
    path('<str:room_name>/', views.room, name='room'),
]