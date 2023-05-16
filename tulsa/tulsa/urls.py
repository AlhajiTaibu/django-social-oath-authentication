"""demo URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from Account.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('account/', include('Account.urls')),
    path('accounts/', include('allauth.urls')),
    path('auth/v1/authenticate/google/', GoogleLogin.as_view(), name='google_login'),
    path('account/facebook/', facebook_login, name='facebook_login')
]

admin.site.site_header = "Tulsa Admin"
admin.site.site_title = "Tulsa Admin Portal"
admin.site.index_title = "Welcome to Tulsa Portal"
