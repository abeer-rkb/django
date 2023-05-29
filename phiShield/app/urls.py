from django.urls import path
from django import views
from .views import *
urlpatterns = [
    path('',  index, name="index"),
    path('classify_view/', classify_view, name='classify_view'),
    path('phishing/', phishing, name='phishing'),
    path('legitimate/', legitimate, name='legitimate'),
]