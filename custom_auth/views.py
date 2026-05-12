from datetime import timedelta
import uuid

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from custom_auth.models import EmailVerificationToken
from custom_auth.tokens import create_access_token
from .serializers import SignupSerializer,OAuthSerializer, LoginSerializer,MFAChallengeSerializer
from django.core.mail import send_mail
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth import authenticate
from .models import RefreshSession, User,SocialAccount
from django.db import transaction
from .models import  BackupCode, LoginEvent
from .utils import (
    generate_sms_otp,
    get_client_ip,
    hash_token,
    verify_sms_otp,
    decrypt,
    encrypt,
    verify_token
)
import pyotp
import requests
import secrets
from django.conf import settings
from django.contrib.auth import login
from .permissions import IsAdmin, IsManager,IsCustomer
from dotenv import load_dotenv
import os

load_dotenv()  # ← top of settings.py, before any os.getenv() calls

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")



class SignupView(APIView):
    permission_classes = [AllowAny]
    

    def post(self, request):
        # check if the middleware flagged the password as pwned
        # This list will contain the key names (e.g., 'password') if found in a breach
        if hasattr(request, 'pwned_passwords') and request.pwned_passwords:
            return Response({
                "error": "Security validation failed.",
                "details": {
                    "password": ["This password has appeared in a data breach and is unsafe to use."]
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Proceed with standard serialization and saving
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
    
    

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "")

       
        #  Authenticate
        request.axes_username = email  # for Axes to log the attempt
        user = authenticate(request, email=email, password=password)

        if not user:
            print("AUTH FAILED")
            LoginEvent.objects.create(
                email=email,
                ip_address=ip,
                user_agent=user_agent,
                success=False
            )
            return Response({"detail": "Invalid credentials"}, status=401)

        # MFA check
        mfa = getattr(user, "mfaprofile", None)
        if mfa and mfa.method != "none":
            if mfa.method == "sms":
                try:
                    generate_sms_otp(user.id)
                except Exception as e:
                    print(f"SMS OTP ERROR: {e}")
                    return Response({"detail": "Failed to send OTP"}, status=500)

            return Response({
                "mfa_required": True,
                "user_id": user.id,
                "method": mfa.method
            })

        # No MFA — issue tokens
        return self._issue_tokens(user, ip, user_agent, mfa_used=False)

    def _issue_tokens(self, user, ip, user_agent, mfa_used):
        
        refresh_token = RefreshToken.for_user(user)

        # HASH TOKEN
        hashed = hash_token(str(refresh_token))

        family_id = uuid.uuid4()

        # STORE SESSION
        session = RefreshSession.objects.create(
            user=user,
            token_hash=hashed,
            expires_at=timezone.now() + timedelta(days=7),
            family_id=family_id,
            user_agent=user_agent,
            ip_address=ip
        )

        # CREATE ACCESS TOKEN
        token = refresh_token.access_token
        access_token = create_access_token(user,session.id,token)
        
        LoginEvent.objects.create(
            user=user,
            email=user.email,
            ip_address=ip,
            user_agent=user_agent,
            success=True,
            mfa_used=mfa_used
        )

        response = Response({
            "access": access_token
        })
        
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=True,
            samesite="Strict",
            max_age=604800
        )
        
        return response
        
        # refresh = RefreshToken.for_user(user)

        # response = Response({
        #     "access": str(refresh.access_token)
        # })

        # response.set_cookie(
        #     key="refresh_token",
        #     value=str(refresh),
        #     httponly=True,
        #     secure=True,
        #     samesite="Strict"
        # )

        # LoginEvent.objects.create(
        #     user=user,
        #     email=user.email,
        #     ip_address=ip,
        #     user_agent=user_agent,
        #     success=True,
        #     mfa_used=mfa_used
        # )

        # return response
        
class RefreshTokenView(APIView):

    permission_classes = [AllowAny]

    def post(self, request):

        refresh_token = request.COOKIES.get("refresh_token")

        if not refresh_token:
            return Response(
                {"detail": "No refresh token"},
                status=401
            )

        sessions = RefreshSession.objects.filter(
            revoked=False
        )

        matched_session = None

        # FIND MATCHING HASH
        for session in sessions:

            if verify_token(
                refresh_token,
                session.token_hash
            ):
                matched_session = session
                break

        if not matched_session:
            return Response(
                {"detail": "Invalid refresh token"},
                status=401
            )

        # EXPIRED
        if matched_session.expires_at < timezone.now():

            matched_session.revoked = True
            matched_session.save()

            return Response(
                {"detail": "Refresh token expired"},
                status=401
            )

        # REUSE DETECTION
        if matched_session.replaced_by:

            # REVOKE ENTIRE FAMILY
            RefreshSession.objects.filter(
                family_id=matched_session.family_id
            ).update(revoked=True)

            return Response(
                {"detail": "Refresh token reuse detected"},
                status=401
            )

        # ROTATE TOKEN

        matched_session.revoked = True
        matched_session.save()

        # CREATE NEW TOKEN
        new_refresh_token =  RefreshToken.for_user(matched_session.user)

        new_hash = hash_token(str(new_refresh_token))

        # CREATE NEW SESSION
        new_session = RefreshSession.objects.create(
            user=matched_session.user,
            token_hash=new_hash,
            expires_at=timezone.now() + timedelta(days=7),
            family_id=matched_session.family_id,
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            ip_address=request.META.get("REMOTE_ADDR")
        )

        # LINK TOKENS
        matched_session.replaced_by = new_session
        matched_session.save()

        # CREATE NEW ACCESS TOKEN
        token = new_refresh_token.access_token
        access_token = create_access_token(
            user=matched_session.user,
            session_id=new_session.id,
            token=token
        )

        response = Response({
            "access": access_token
        })

        # NEW COOKIE
        response.set_cookie(
            key="refresh_token",
            value=new_refresh_token,
            httponly=True,
            secure=True,
            samesite="Strict",
            max_age=604800
        )

        return response        


class MFAChallengeView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = MFAChallengeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_id = serializer.validated_data['user_id']
        method = serializer.validated_data['method']
        code = serializer.validated_data['code']

        ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "")

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(status=401)

        mfa = user.mfaprofile

        valid = False

        # TOTP
        if method == "totp":
            secret = decrypt(mfa.totp_secret_encrypted)
            totp = pyotp.TOTP(secret)
            valid = totp.verify(code, valid_window=1)

        # SMS
        elif method == "sms":
            valid = verify_sms_otp(user_id, code)

        # Backup codes
        elif method == "backup":
            with transaction.atomic():
                codes = BackupCode.objects.select_for_update().filter(
                    user=user,
                    used=False
                )

                for c in codes:
                    if c.redeem(code):
                        valid = True
                        break

        if not valid:
            return Response({"detail": "Invalid code"}, status=401)

        #Issue tokens
        refresh = RefreshToken.for_user(user)

        response = Response({
            "access": str(refresh.access_token)
        })

        response.set_cookie(
            key="refresh_token",
            value=str(refresh),
            httponly=True,
            secure=True,
            samesite="Strict"
        )

        LoginEvent.objects.create(
            user=user,
            email=user.email,
            ip_address=ip,
            user_agent=user_agent,
            success=True,
            mfa_used=True
        )


        return response    


class GoogleLoginView(APIView):

    permission_classes = [AllowAny]

    def post(self, request):

        serializer = OAuthSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data["code"]

        token_url = "https://oauth2.googleapis.com/token"

        data = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": "http://localhost:5500/callback.html",
            "grant_type": "authorization_code",
        }

        token_response = requests.post(token_url, data=data)

        if token_response.status_code != 200:
            return Response(
                {"detail": "Google token exchange failed"},
                status=400
            )

        token_json = token_response.json()

        access_token = token_json.get("access_token")

        userinfo_response = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={
                "Authorization": f"Bearer {access_token}"
            }
        )

        user_data = userinfo_response.json()

        email = user_data["email"]
        provider_user_id = user_data["id"]

        user = User.objects.filter(email=email).first()

        if not user:
            user = User.objects.create(
                email=email,
                is_verified=True
            )

            user.set_unusable_password()
            user.save()

        SocialAccount.objects.get_or_create(
            provider="google",
            provider_user_id=provider_user_id,
            defaults={
                "user": user,
                "extra_data": user_data
            }
        )

        refresh = RefreshToken.for_user(user)

        response = Response({
            "access": str(refresh.access_token),
            "user": {
                "id": user.id,
                "email": user.email,
            }
        })

        response.set_cookie(
            key="refresh_token",
            value=str(refresh),
            httponly=True,
            secure=True,
            samesite="Strict"
        )

        return response


# -----------------------------------
# GITHUB LOGIN
# -----------------------------------

class GitHubLoginView(APIView):

    permission_classes = [AllowAny]

    def post(self, request):

        serializer = OAuthSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data["code"]

        token_response = requests.post(
            "https://github.com/login/oauth/access_token",
            headers={
                "Accept": "application/json"
            },
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
            }
        )

        if token_response.status_code != 200:
            return Response(
                {"detail": "GitHub token exchange failed"},
                status=400
            )

        token_json = token_response.json()

        access_token = token_json.get("access_token")

        user_response = requests.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}"
            }
        )

        user_data = user_response.json()

        email_response = requests.get(
            "https://api.github.com/user/emails",
            headers={
                "Authorization": f"Bearer {access_token}"
            }
        )

        emails = email_response.json()

        primary_email = None

        for e in emails:
            if e.get("primary"):
                primary_email = e["email"]
                break

        if not primary_email:
            return Response(
                {"detail": "No primary email found"},
                status=400
            )

        provider_user_id = str(user_data["id"])

        user = User.objects.filter(email=primary_email).first()

        if not user:
            user = User.objects.create(
                email=primary_email,
                is_verified=True

            )

            user.set_unusable_password()
            user.save()

        SocialAccount.objects.get_or_create(
            provider="github",
            provider_user_id=encrypt(provider_user_id),
            defaults={
                "user": user,
                "extra_data": user_data
            }
        )

        refresh = RefreshToken.for_user(user)

        response = Response({
            "access": str(refresh.access_token),
            "user": {
                "id": user.id,
                "email": user.email,
            }
        })

        response.set_cookie(
            key="refresh_token",
            value=str(refresh),
            httponly=True,
            secure=True,
            samesite="Strict"
        )

        return response
    
    
class AddProductView(APIView):
    permission_classes = [IsManager,IsAuthenticated]    
    
    def get(self,request):
        return Response({
            'message':'Manager added products',
            'email':request.user.email,
            'role':request.user.role        
        })

class AddManagerView(APIView):
    permission_classes = [IsAdmin,IsAuthenticated]    
    
    def get(self,request):
        return Response({
            'message':'Admin added Manager',
            'email':request.user.email,
            'role':request.user.role        
        })


              