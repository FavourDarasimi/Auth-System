from django.apps import AppConfig


class CustomAuthConfig(AppConfig):
    name = 'custom_auth'
    
    def ready(self):
        from custom_auth import signals 
