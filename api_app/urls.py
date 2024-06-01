from django.urls import path
from . import views

urlpatterns = [
    #path('', views.success, name='success'),
    path('success/', views.success, name='success'),
]