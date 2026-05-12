from rest_framework_simplejwt.tokens import AccessToken


def create_access_token(user, session_id,token):

    token["user_id"] = str(user.id)
    token["email"] = user.email
    token["role"] = user.role
    token["session_id"] = str(session_id)

    return str(token)