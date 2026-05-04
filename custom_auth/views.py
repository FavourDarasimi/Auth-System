from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from custom_auth.models import EmailVerificationToken
from .serializers import SignupSerializer
from django.core.mail import send_mail
from django.urls import reverse
from django.utils import timezone


class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # 1. First, check if the middleware flagged the password as pwned
        # This list will contain the key names (e.g., 'password') if found in a breach
        if hasattr(request, 'pwned_passwords') and request.pwned_passwords:
            return Response({
                "error": "Security validation failed.",
                "details": {
                    "password": ["This password has appeared in a data breach and is unsafe to use."]
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # 2. Proceed with standard serialization and saving
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Generate tokens immediately after signup
            refresh = RefreshToken.for_user(user)
            
            # Create a verification token and send verification email
            token = EmailVerificationToken.objects.create(user=user)
            link = f"localhost:8000{reverse('verify-email', args=[token.token])}"
            send_mail(
                "Verify your account",
                f"Click here to verify: {link}",
                "noreply@yourdomain.com",
                [user.email],
            )
            
            return Response({
                "message": "Account created successfully.",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "is_verified": user.is_verified,
                    "created_at": user.created_at,
                    "token":token.token
                },
                "tokens": {
                    "refresh": str(refresh),
                    "access":  str(refresh.access_token),
                }
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class VerifyEmailView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request, token):
        try:
            obj = EmailVerificationToken.objects.get(token=token)
        except:
            return Response({"error": "Invalid token"}, status=400)

        if obj.expires_at < timezone.now():
            return Response({"error": "Token expired"}, status=400)

        user = obj.user
        user.is_verified = True
        user.save()

        obj.is_used = True
        obj.verified_at = timezone.now()
        obj.save()

        return Response({"message": "Email verified"})