from django.contrib.auth.models import AbstractUser
from django.db import models

# Create your models here.
class CustomUser(AbstractUser):
    # Creates image for all users on their profile page
    avatar = models.ImageField(blank=True, null=True, default='avatars/default.png')
    # is_verified = models.BooleanField(default=True)
    otp = models.CharField(max_length=20, null=True, blank=True)
    otp_created_time = models.DateTimeField(null=True, blank=True)
    otp_enabled = models.BooleanField(default=False)
    otp_verified = models.BooleanField(default=False)
    otp_base32 = models.CharField(max_length=255, null=True, blank=True)
    otp_auth_url = models.CharField(max_length=255, null=True, blank=True)
    user_otp_qrcode = models.ImageField(upload_to='otp_qr_code', null=True, blank=True)