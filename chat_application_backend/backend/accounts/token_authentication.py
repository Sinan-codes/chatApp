import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.conf import settings
from django.contrib.auth import get_user_model
from datetime import datetime, timedelta


class JWTAuthentication(BaseAuthentication):


    def authenticate(self, request):
        token = self.extract_token(request)
        if token is None:
            return None
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            self.verify_token(payload=payload)

            user_id = payload.get("id")
            User = get_user_model()
            user = User.objects.get(id=user_id)
            return user
        except (InvalidTokenError, ExpiredSignatureError):
            raise AuthenticationFailed("Invalid or expired token")
        except Exception:
            raise AuthenticationFailed("Invalid or expired token")


    def verify_token(self, payload):
        if "exp" not in payload:
            raise InvalidTokenError("Token missing expiration")

        exp_timestamp = payload["exp"]
        current_timestamp = datetime.utcnow().timestamp()

        if current_timestamp > exp_timestamp:
            raise ExpiredSignatureError("Token has expired")


    def extract_token(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION")
        if auth_header and auth_header.startswith("Bearer "):
            return auth_header.split(" ")[1]

        return None


    def generate_token(payload):
        expiration = datetime.utcnow() + timedelta(hours=24)
        payload["exp"] = expiration
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
        return token