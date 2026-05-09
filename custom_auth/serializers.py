from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

User = get_user_model()

class SignupSerializer(serializers.ModelSerializer):
    password  = serializers.CharField(write_only=True, validators=[validate_password])
    

    class Meta:
        model  = User
        fields = [ 'email', 'password']


    def create(self, validated_data):
        user = User.objects.create_user(**validated_data,is_verified=False)
        return user
    
class LoginSerializer(serializers.ModelSerializer):
    password  = serializers.CharField(write_only=True, validators=[validate_password])
    class Meta:
        model = User
        fields = [ 'email', 'password']    
        
class MFAChallengeSerializer(serializers.Serializer):
    METHOD_CHOICES = (
        ("none", "None"),
        ("totp", "TOTP"),
        ("sms", "SMS"),
    )
    user_id = serializers.UUIDField()
    method = serializers.ChoiceField(choices=METHOD_CHOICES) 
    code = serializers.CharField()       
    
class OAuthSerializer(serializers.Serializer):

    code = serializers.CharField()   
    
     