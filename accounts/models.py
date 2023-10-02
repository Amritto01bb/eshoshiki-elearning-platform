import os

from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils import timezone


# Supporting functions
def remove_temp_files(img_dir_filepath):
    dir_filepath = os.path.join(settings.MEDIA_ROOT, img_dir_filepath)
    if os.path.exists(dir_filepath):
        for filename in os.listdir(dir_filepath):
            if "temp_" + img_dir_filepath in str(filename):
                file_path = os.path.join(dir_filepath, filename)
                os.remove(file_path)


# Account model
def get_default_profile_img_filepath():
    return "default/default_profile_img.png"


def get_profile_img_filepath(self, filename):
    remove_temp_files("profile_img")
    return "profile_img/temp_profile_img." + filename.split('.')[-1]


class AccountManager(BaseUserManager):
    def create_user(self, username, email, password=None):
        if not username:
            raise ValueError('Users must have a username')
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(username=username, email=self.normalize_email(email))
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password):
        user = self.create_user(username=username, email=self.normalize_email(email), password=password)
        user.is_superuser = True
        user.is_admin = True
        user.is_staff = True
        user.is_instructor = True
        user.is_verified = True
        user.is_active = True
        user.save(using=self._db)
        return user


class Account(AbstractBaseUser, PermissionsMixin):
    date_joined = models.DateTimeField(verbose_name='Date Joined', auto_now_add=True)
    last_login = models.DateTimeField(verbose_name='Last Login', auto_now=True)

    is_superuser = models.BooleanField(verbose_name="Is Superuser", null=False, blank=False, default=False)
    is_admin = models.BooleanField(verbose_name="Is Admin", null=False, blank=False, default=False)
    is_staff = models.BooleanField(verbose_name="Is Staff", null=False, blank=False, default=False)
    is_instructor = models.BooleanField(verbose_name="Is Expert", null=False, blank=False, default=False)
    is_verified = models.BooleanField(verbose_name="Is Verified", null=False, blank=False, default=False)
    is_active = models.BooleanField(verbose_name="Is Active", null=False, blank=False, default=False)

    image = models.ImageField(verbose_name='Image', max_length=255, null=False, blank=False, default=get_default_profile_img_filepath, upload_to=get_profile_img_filepath)
    first_name = models.CharField(verbose_name="First Name", max_length=32, null=False, blank=False)
    last_name = models.CharField(verbose_name="Last Name", max_length=32, null=True, blank=True)

    username = models.CharField(verbose_name="Username", max_length=255, null=False, blank=False, unique=True)
    email = models.EmailField(verbose_name="Email", max_length=255, null=False, blank=False, unique=True)
    password = models.CharField(verbose_name="Password", max_length=255, null=False, blank=False)

    phone = models.CharField(verbose_name="Phone", max_length=64, null=False, blank=False)
    reputation = models.IntegerField(verbose_name="Reputation", null=False, blank=False, default=0)

    objects = AccountManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return str(self.id)

    @property
    def unread_notifications(self):
        notifications = self.notifications.all()
        count = 0
        for notification in notifications:
            if not notification.is_read:
                count += 1

        return count

    def get_name(self):
        name = ''
        if self.first_name and self.last_name:
            name = str(self.first_name) + ' ' + str(self.last_name)
        elif self.first_name:
            name = str(self.first_name)
        elif self.last_name:
            name = str(self.last_name)

        return name

    def get_short_name(self):
        name = ''
        if self.first_name:
            name = str(self.first_name)
        elif self.last_name:
            name = str(self.last_name)

        return name

    def has_perm(self, perm, obj=None):
        # Superusers have all permissions
        if self.is_active and self.is_superuser:
            return True

        # Otherwise, use the standard method to check permissions
        return super().has_perm(perm, obj=obj)

    def has_module_perms(self, app_label):
        # If the user is a superuser or an admin, return True
        if self.is_active:
            if self.is_superuser or self.is_admin:
                return True

        # Check all the permissions of the user
        for perm in self.user_permissions.all():
            if perm.content_type.app_label == app_label:
                return True

        # Check all the permissions of the user's groups
        for group in self.groups.all():
            for perm in group.permissions.all():
                if perm.content_type.app_label == app_label:
                    return True

        # If no permissions matched, return False
        return False

    class Meta:
        verbose_name_plural = "Accounts"


# Token model
class Token(models.Model):
    created = models.DateTimeField(verbose_name='Created', auto_now_add=True)
    last_modified = models.DateTimeField(verbose_name="Last Modified", auto_now=True)
    account = models.ForeignKey(Account, null=False, blank=False, on_delete=models.CASCADE, related_name='tokens')
    token = models.CharField(verbose_name="Token", max_length=255, null=False, blank=False)
    expire_date = models.DateTimeField(verbose_name="Expire Date", null=False, blank=False)
    is_valid = models.BooleanField(verbose_name="Is Valid", null=False, blank=False, default=True)

    def __str__(self):
        return str(self.id)

    @property
    def is_expired(self):
        if self.is_valid and timezone.now() > self.expire_date:
            self.is_valid = False
            self.save()

        return not self.is_valid

    def save(self, *args, **kwargs):
        if not self.id:
            # Set the expiration date to be 5 minutes from now
            self.expire_date = timezone.now() + timezone.timedelta(minutes=5)

        super().save(*args, **kwargs)

    class Meta:
        verbose_name_plural = "Tokens"


# Notification model
class Notification(models.Model):
    timestamp = models.DateTimeField(verbose_name='Send Time', auto_now_add=True)
    account = models.ForeignKey(Account, null=False, blank=False, on_delete=models.CASCADE, related_name='notifications')
    notification = models.CharField(verbose_name="Notification", max_length=255, null=False, blank=False)
    is_read = models.BooleanField(verbose_name="Read", null=False, blank=False, default=False)

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = "Notifications"
