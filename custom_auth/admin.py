from django.contrib import admin
from .models import User,EmailVerificationToken

admin.site.register(User)
admin.site.register(EmailVerificationToken)
# Register your models here.
