import secrets
from django.core.cache import cache
from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth.hashers import (
    make_password,
    check_password
)

fernet = Fernet(settings.FERNET_KEY)


def get_client_ip(request):
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0]
    return request.META.get("REMOTE_ADDR")


# SMS OTP
def generate_sms_otp(user_id):
    code = secrets.randbelow(900000) + 100000
    cache.set(f"sms_otp:{user_id}", str(code), timeout=300)
    print(f"[SMS OTP] {code}")  # replace with real provider
    return code


def verify_sms_otp(user_id, code):
    stored = cache.get(f"sms_otp:{user_id}")
    if not stored:
        return False

    if secrets.compare_digest(str(stored), str(code)):
        cache.delete(f"sms_otp:{user_id}")
        return True
    return False


# Encryption
def encrypt(value):
    return fernet.encrypt(value.encode()).decode()


def decrypt(value):
    return fernet.decrypt(value.encode()).decode()

def hash_token(token):
    return make_password(token)


def verify_token(raw_token, hashed_token):
    return check_password(raw_token, hashed_token)

# ACCESS TOKEN BLACKLIST

def blacklist_access_token(jti, exp_seconds):
    cache.set(
        f"blacklist:{jti}",
        "true",
        timeout=exp_seconds
    )


def is_blacklisted(jti):
    return cache.get(f"blacklist:{jti}") is not None