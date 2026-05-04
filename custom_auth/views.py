from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import SignupSerializer

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
            return Response({
                "message": "Account created successfully.",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "username": user.username,
                },
                "tokens": {
                    "refresh": str(refresh),
                    "access":  str(refresh.access_token),
                }
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
