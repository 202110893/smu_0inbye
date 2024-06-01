from django.urls import path
from kakaopay import views

app_name = 'kakaopay'

urlpatterns = [
    path('kakaoPay/', views.kakaopay, name='kakaopay'),
    path('', views.index, name='index'),
    path('paySuccess/', views.paySuccess, name='paySuccess'),
    path('payFail/', views.payFail, name='payFail'),
    path('payCancel/', views.payCancel, name='payCancel'),
]