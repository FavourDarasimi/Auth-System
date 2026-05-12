from django.contrib import admin
from .models import RefreshSession,PasswordResetToken, User,EmailVerificationToken,MFAProfile,LoginEvent,BackupCode,SocialAccount

admin.site.register(User)
admin.site.register(EmailVerificationToken)
admin.site.register(MFAProfile)
admin.site.register(LoginEvent)
admin.site.register(BackupCode)
admin.site.register(SocialAccount)
admin.site.register(RefreshSession)
admin.site.register(PasswordResetToken)
# Register your models here.
