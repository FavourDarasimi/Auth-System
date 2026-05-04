from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

User = get_user_model()

class SignupSerializer(serializers.ModelSerializer):
    password  = serializers.CharField(write_only=True, validators=[validate_password])
    

    class Meta:
        model  = User
        fields = ['username', 'email', 'password']


    def create(self, validated_data):
        user = User.objects.create_user(**validated_data,is_verified=False)
        return user