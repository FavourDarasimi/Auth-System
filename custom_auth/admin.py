from django.contrib import admin
from .models import User,EmailVerificationToken,MFAProfile,LoginEvent,BackupCode

admin.site.register(User)
admin.site.register(EmailVerificationToken)
admin.site.register(MFAProfile)
admin.site.register(LoginEvent)
admin.site.register(BackupCode)
# Register your models here.
