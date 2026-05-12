from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import ForgotPasswordView, GitHubLoginView, GoogleLoginView, LogoutView, ResetPasswordView, SignupView,VerifyEmailView,LoginView, MFAChallengeView,ChangeMFAChallengeStatusView,RefreshTokenView

urlpatterns = [
    path('signup/',SignupView.as_view(),name='signup'),
    path('token/refresh/',RefreshTokenView.as_view(),name='token_refresh'),
    path('verify-email/<str:token>/', VerifyEmailView.as_view(), name='verify-email'),
    path("login/", LoginView.as_view()),
    path("mfa/challenge/", MFAChallengeView.as_view()),
    path("google/",GoogleLoginView.as_view(),name="google-login"),
    path("github/",GitHubLoginView.as_view(),name="github-login"),
    path("add/mfa-profile/",ChangeMFAChallengeStatusView.as_view(),name="add-mfa-profile"),
    path("forgot-password/",ForgotPasswordView.as_view(),name="forgot-password"),
    path("reset-password/",ResetPasswordView.as_view(),name="reset-password"),
    path("logout/",LogoutView.as_view()),
]


