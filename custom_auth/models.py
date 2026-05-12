from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
import uuid
from django.utils import timezone
from datetime import timedelta





class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)
    
class User(AbstractBaseUser,PermissionsMixin):
    ROLE_CHOICES = (
    ("admin", "Admin"),
    ("manager", "Manager"),
    ("customer", "Customer"),
    )

   
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=20,choices=ROLE_CHOICES,default="customer")
    is_verified = models.BooleanField(default=False)
    is_active  = models.BooleanField(default=True)
    is_staff   = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    objects = UserManager()

    USERNAME_FIELD  = 'email'       
    REQUIRED_FIELDS = []           

    def __str__(self):
        return self.email


class EmailVerificationToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    def __str__(self):
        return f'{self.user.email} Token'

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=30)
        super().save(*args, **kwargs)



class MFAProfile(models.Model):
    METHOD_CHOICES = (
        ("none", "None"),
        ("totp", "TOTP"),
        ("sms", "SMS"),
    )

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    method = models.CharField(max_length=10, choices=METHOD_CHOICES, default="none")
    totp_secret_encrypted = models.TextField(null=True, blank=True)
    
    def __str__(self):
        return f'{self.user.email} MFA Profile'


class BackupCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code_hash = models.CharField(max_length=255)
    used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f'{self.email} Backup Code'

    def redeem(self, raw_code):
        from django.contrib.auth.hashers import check_password

        if self.used:
            return False

        if check_password(raw_code, self.code_hash):
            self.used = True
            self.used_at = timezone.now()
            self.save()
            return True
        return False


class LoginEvent(models.Model):
    user = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
    email = models.EmailField()
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    success = models.BooleanField()
    mfa_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True) 
    
    def __str__(self):
        return f'{self.email} Event'
    
class SocialAccount(models.Model):

    PROVIDERS = (
        ("google", "Google"),
        ("github", "GitHub"),
    )

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="social_accounts"
    )

    provider = models.CharField(max_length=50, choices=PROVIDERS)

    provider_user_id = models.CharField(max_length=255)

    extra_data = models.JSONField(default=dict)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("provider", "provider_user_id")

    def __str__(self):
        return f"{self.user.email} - {self.provider}"    
    
class RefreshSession(models.Model):

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE
    )

    token_hash = models.CharField(max_length=255)

    created_at = models.DateTimeField(auto_now_add=True)

    expires_at = models.DateTimeField()

    revoked = models.BooleanField(default=False)

    replaced_by = models.OneToOneField(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL
    )

    family_id = models.UUIDField(default=uuid.uuid4)

    user_agent = models.TextField(blank=True)

    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True
    )

    def __str__(self):
        return f"{self.user.email} - {self.id}"    