from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import GitHubLoginView, GoogleLoginView, SignupView,VerifyEmailView,LoginView, MFAChallengeView

urlpatterns = [
    path('signup/',SignupView.as_view(),name='signup'),
    path('token/refresh/',TokenRefreshView.as_view(),name='token_refresh'),
    path('verify-email/<str:token>/', VerifyEmailView.as_view(), name='verify-email'),
    path("login/", LoginView.as_view()),
    path("mfa/challenge/", MFAChallengeView.as_view()),
    path("google/",GoogleLoginView.as_view(),name="google-login"),
    path("github/",GitHubLoginView.as_view(),name="github-login"),
]


