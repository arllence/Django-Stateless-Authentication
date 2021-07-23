import os
import uuid
import datetime
from uuid import uuid4
from django.db import models
from storage import smb_storage
from django.conf import settings
from .managers import UserManager
from django.contrib.postgres.fields import JSONField
from django.contrib.auth.models import Group, PermissionsMixin
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser

media_mode = settings.MAINMEDIA
smb_system_storage = smb_storage.SMBStorage()

class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    registry = models.CharField(max_length=200)
    department = models.CharField(max_length=200)
    username = models.CharField(max_length=100, unique=True)
    id_number = models.CharField(max_length=50)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    is_active = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_defaultpassword = models.BooleanField(default=True)
    is_applicant = models.BooleanField(default=False)
    is_department_admin = models.BooleanField(default=False)
    is_approver = models.BooleanField(default=False)
    is_business_analyst = models.BooleanField(default=False)
    is_suspended = models.BooleanField(null=True)
    last_password_reset = models.DateTimeField(auto_now=True)
    objects = UserManager()

    USERNAME_FIELD = "username"

    def __str__(self):
        return str(self.username)

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    class Meta:
        db_table = "systemusers"


class AccountActivity(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    recipient = models.ForeignKey(
        User, related_name="user_account_activity", on_delete=models.CASCADE
    )
    actor = models.ForeignKey(
        User, related_name="activity_actor", on_delete=models.CASCADE
    )
    activity = models.TextField(null=True, blank=True)
    remarks = models.TextField(null=True, blank=True)
    action_time = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "user_manager"
        db_table = "account_activity"

    def __str__(self):
        return str(self.id)


