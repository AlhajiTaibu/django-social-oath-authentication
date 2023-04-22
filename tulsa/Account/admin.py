from django.contrib import admin
from .models import User


class UserAdmin(admin.ModelAdmin):
    list_display = ['email', 'username', 'is_active', 'is_staff', 'is_activated']
    list_filter = ['is_staff', ]


admin.site.register(User, UserAdmin)
