# accounts/validators.py
import re
from django.core.exceptions import ValidationError

class StrongPasswordValidator:
    def validate(self, password, user=None):
        if not re.search(r"[A-Z]", password):
            raise ValidationError("Password must contain an uppercase letter")

        if not re.search(r"[a-z]", password):
            raise ValidationError("Password must contain a lowercase letter")

        if not re.search(r"\d", password):
            raise ValidationError("Password must contain a number")

        if not re.search(r"[!@#$%^&*]", password):
            raise ValidationError("Password must contain a special character")

    def get_help_text(self):
        return "Your password must contain uppercase, lowercase, number, and special character."