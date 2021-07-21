import jwt
from rest_framework import authentication, exceptions
from edms.models import User
from rest_framework import status
from datetime import datetime, timedelta
from django.conf import settings


class SystemApiAuthentication(authentication.BaseAuthentication):

    authentication_header_prefix = 'Bearer'

    def authenticate(self, request):
        """
        The `authenticate` method is called on every request regardless of
        whether the endpoint requires authentication. 

        `authenticate` has two possible return values:

        1) `None` - We return `None` if we do not wish to authenticate. Usually
                    this means we know authentication will fail. An example of
                    this is when the request does not include a token in the
                    headers.

        2) `(user, token)` - We return a user/token combination when 
                             authentication is successful.

                            If neither case is met, that means there's an error 
                            and we do not return anything.
                            We simple raise the `AuthenticationFailed` 
                            exception and let Django REST Framework
                            handle the rest.
        """
        request.user = None

        # `auth_header` should be an array with two elements: 1) the name of
        # the authentication header (in this case, "Token") and 2) the JWT
        # that we should authenticate against.
        auth_header = authentication.get_authorization_header(request).split()

        auth_header_prefix = self.authentication_header_prefix.lower()

        if not auth_header:
            return None

        if len(auth_header) == 1:
            # Invalid token header. No credentials provided. Do not attempt to
            # authenticate.
            raise exceptions.NotAuthenticated(
                {"message": "Could Not Authenticate User", "code": status.HTTP_401_UNAUTHORIZED})

        elif len(auth_header) > 2:
            # Invalid token header. The Token string should not contain spaces. Do
            # not attempt to authenticate.
            raise exceptions.NotAuthenticated(
                {"message": "Could Not Authenticate,Invalid Values Passed", "code": status.HTTP_401_UNAUTHORIZED})

        # The JWT library we're using can't handle the `byte` type, which is
        # commonly used by standard libraries in Python 3. To get around this,
        # we simply have to decode `prefix` and `token`. This does not make for
        # clean code, but it is a good decision because we would get an error
        # if we didn't decode these values.
        try:

            prefix = auth_header[0].decode('utf-8')
            token = auth_header[1].decode('utf-8')

        except:
            raise exceptions.NotAcceptable(
                {"message": "No Token Present", "code": status.HTTP_406_NOT_ACCEPTABLE})

        if prefix.lower() != auth_header_prefix:
            # The auth header prefix is not what we expected. Do not attempt to
            # authenticate.
            return None

        # By now, we are sure there is a *chance* that authentication will
        # succeed. We delegate the actual credentials authentication to the
        # method below.

        return self._authenticate_credentials(request, token)

    def _authenticate_credentials(self, request, token):
        """
        Try to authenticate the given credentials. If authentication is
        successful, return the user and token. If not, throw an error.
        """
        try:
            payload = jwt.decode(token, settings.TOKEN_SECRET_CODE)
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed(
                {"message": "User Logged Out.Please Try Again", "code": status.HTTP_401_UNAUTHORIZED})

        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed(
                {"message": "Please Try Logging In Again", "code": status.HTTP_401_UNAUTHORIZED})

        except Exception as e:
            raise exceptions.AuthenticationFailed(
                {"message": "Invalid Verification", "code": status.HTTP_401_UNAUTHORIZED})

        try:
            user = User.objects.get(id=payload['id'])
        except User.DoesNotExist:

            raise exceptions.AuthenticationFailed(
                {"message": "No User Matching record found", "code": status.HTTP_401_UNAUTHORIZED})

        if not user.is_active:

            raise exceptions.AuthenticationFailed(
                {"message": "User Account is Deactivated", "code": status.HTTP_401_UNAUTHORIZED})

        return (user, token)
