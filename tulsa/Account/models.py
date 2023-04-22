from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.core.management.utils import get_random_secret_key



class UserManager(BaseUserManager):
    def create_user(self, email='', password=None, username=''):
        print(f'email={email}')
        if not email and not validate_email(email):
            raise ValidationError("Please provide a valid email")

        user = self.model(
            email=self.normalize_email(email),
            username=username,
        )
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email='', password=None, username=''):
        if not email and not validate_email(email):
            raise ValidationError("Please provide a valid email")

        user = self.create_user(email, password=password, username=username)
        user.is_admin = True
        user.is_staff = True
        user.save()
        return user


class User(AbstractBaseUser):
    email = models.EmailField(max_length=254,unique=True)
    username = models.CharField(max_length=150)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_activated = models.BooleanField(default=False)

    objects = UserManager()
    USERNAME_FIELD = "email"

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        # "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, Auth):
        # "Does the user have permissions to view the app Auth?"
        # Simplest possible answer: Yes, always
        return True

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)


