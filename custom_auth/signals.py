from django.dispatch import receiver
from axes.signals import user_locked_out
from rest_framework.exceptions import PermissionDenied

from .models import LoginEvent
from .utils import get_client_ip


@receiver(user_locked_out)
def on_user_locked_out(sender, request, username, **kwargs):

    ip = get_client_ip(request)
    user_agent = request.META.get("HTTP_USER_AGENT", "")
    email = username or request.POST.get("email") or request.data.get("email", "")

    LoginEvent.objects.create(
        email=email,
        ip_address=ip,
        user_agent=user_agent,
        success=False,
    )

    raise PermissionDenied("Account Locked")