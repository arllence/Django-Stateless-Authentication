import jwt
from django.contrib.postgres.fields import JSONField
from django.contrib.auth import authenticate
from django.http import JsonResponse
from user_manager.models import SystemUser, mobiledevices
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.exceptions import APIException
from rest_framework import HTTP_HEADER_ENCODING, exceptions
from rest_framework import status
from rest_framework.response import Response
from django.http import HttpResponse
from promicsweb import settings as C
from datetime import datetime, timedelta, date
import time


class AppAuthentication:
    """
    Class to authenticate the current user against the credentials and generate a token
    The payload can be used for both mobile and web
    For mobile, authtype is mob, while for web the auth type is web
    For mobile the device uuid must exist while for web this is not required
    """

    def __init__(self):
        pass

    def validateuser(self, payload):

        incomingdata = payload

        username = incomingdata['username']
        password = incomingdata['password']
        authtype = incomingdata['authtype']
        if authtype == 'mob':
            # - check whether if the device exists
            deviceuuid = incomingdata['deviceuuid']
            deviceimei = incomingdata['deviceimei']
            deviceexists = mobiledevices.objects.filter(
                imeino=deviceimei, deviceuuid=deviceuuid).exists()
            if deviceexists:
                return self.authenticateuser(username, password)

            else:
                raise exceptions.NotFound(
                    {"message": "Device Does Not Exist", "code": status.HTTP_404_NOT_FOUND})
        elif authtype == 'web':
            return self.authenticateuser(username, password)
        else:
            raise exceptions.NotFound(
                {"message": "Invalid Authentication Type", "code": status.HTTP_404_NOT_FOUND})

    def authenticateuser(self, incomingusername, incomingpassword):
        user = authenticate(username=incomingusername,
                            password=incomingpassword)
        # --if user authentication is right, then return a token
        if user:
            payload = {
                'id': user.pk,
                'username': user.username,
                'department': user.department.id,
                'staff': user.is_staff,
                'exp': datetime.utcnow() + timedelta(seconds=C.EXPIRY_TIME),
                'iat': datetime.utcnow()
            }
            token = jwt.encode(payload, C.TOKEN_SECRET_KEY)
            # --retuning the generated token
            userinfo = {
                "token": token,
                "username": user.username
            }
            return userinfo

        raise APIException(
            {"message": "Invalid Username / Password", "code": status.HTTP_403_FORBIDDEN})

    def token_expires_in(self, token):

        currenttime = int(time.time())
        time_elapsed = int(currenttime) - int(token['exp'])
        left_time = timedelta(hours=C.EXPIRY_TIME) - time_elapsed
        return left_time
