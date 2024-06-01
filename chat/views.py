# chat/views.py
from django.shortcuts import render

def chatting(request):
    return render(request, 'chat/chatting.html')

def room(request, room_name):
    return render(request, 'chat/room.html', {
        'room_name': room_name
    })