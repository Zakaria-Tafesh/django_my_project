
from django.urls import path
from .api import (RegistrationAPI,
                  LoginAPI,
                  UserAPI,
                  change_password)
from knox import views as knox_views

urlpatterns = [
    path('register/', RegistrationAPI.as_view()),
    path('login/', LoginAPI.as_view()),
    path('user/', UserAPI.as_view()),

    path('logout/', knox_views.LogoutView.as_view(), name='logout'),
    path('logoutall/', knox_views.LogoutAllView.as_view(), name='logoutall'),

    path('change/', change_password, name='change_password'),

]
