from django.urls import path

from .views import RegistrationView, index, profile, lol, Authentication,  ActivateView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('login', Authentication.as_view(), name="login"),
    path('activate/<uidb64>/<token>', ActivateView.as_view(), name='activate'),
    # path('google_login', GoogleLogin.as_view(), name="google_login"),
    # path('logout', Authentication.as_view(), name="logout"),
    # path('facebook/', facebook_login, name="facebook_login"),
    path('register', RegistrationView.as_view(), name="register"),
    path('send', index),
    path('lol', lol),
    path('profile', profile),
    path(
        'token/refresh/',
        TokenRefreshView.as_view(),
        name='token_refresh'
    )
]
