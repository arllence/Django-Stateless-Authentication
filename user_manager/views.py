from rest_framework.views import APIView
from user_manager import serializers
# from edms import models
from . import models
from django.contrib.auth import authenticate
from rest_framework.decorators import action
from rest_framework.response import Response
from django.contrib.auth.models import Permission
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import viewsets, status
import json
import jwt
import random
import re
from django.conf import settings
from django.utils import timezone
# from dateutil.relativedelta import relativedelta
from datetime import datetime, timedelta, date
from user_manager.utils import user_util
from django.contrib.auth.hashers import make_password, check_password
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, Group
from django.db import IntegrityError, transaction


class AuthenticationViewSet(viewsets.ModelViewSet):
    permission_classes = (AllowAny,)
    queryset = models.User.objects.all().order_by('id')
    serializer_class = serializers.SystemUsersSerializer
    search_fields = ['id', ]

    def get_queryset(self):
        return []

    @action(methods=["POST"], detail=False, url_path="login", url_name="login")
    def login_user(self, request):
        payload = request.data
        username = request.data.get('username')
        password = request.data.get('password')
        if username is None:
            return Response({"details": "Username is required"}, status=status.HTTP_400_BAD_REQUEST)
        if password is None:
            return Response({"details": "Password is required"}, status=status.HTTP_400_BAD_REQUEST)
        input_username = payload['username']
        input_password = payload['password']
        
        is_authenticated = authenticate(
            username=input_username, password=input_password)

        if is_authenticated: 
            # print("now_aware", now_aware)
            last_password_reset = is_authenticated.last_password_reset
            # print("last_password_reset",last_password_reset)
            now_date = datetime.now(timezone.utc)
            # print("now_date",now_date)
            last_reset = (now_date - last_password_reset).days
            # print("date_diff", last_reset)

            # last_reset = 30

            if last_reset >= 30:
                change_password = True
            else:
                change_password = is_authenticated.is_defaultpassword

            is_suspended = is_authenticated.is_suspended
            if is_suspended is True or is_suspended is None:
                return Response({"details": "Your Account Has Been Suspended,Liase with your supervisor"}, status=status.HTTP_400_BAD_REQUEST)
            else:
                user_department = is_authenticated.department
                if user_department is None or not user_department:
                    department_name = " "
                    department_id = " "
                else:
                    department_id = str(is_authenticated.department.id)
                    department_name = str(is_authenticated.department.name)

                payload = {
                    'id': str(is_authenticated.id),
                    'username': is_authenticated.username,
                    'department_id': department_id,
                    'department_name': department_name,
                    'password_change_status': change_password,
                    'staff': is_authenticated.is_staff,
                    'exp': datetime.utcnow() + timedelta(seconds=settings.TOKEN_EXPIRY),
                    'iat': datetime.utcnow()
                }
                token = jwt.encode(payload, settings.TOKEN_SECRET_CODE)
                # roles = user_util.fetchusergroups(is_authenticated.id)
                response_info = {
                    "token": token,
                    # "roles":roles,
                    # "username":is_authenticated.username,
                    "change_password": change_password
                }
                return Response(response_info, status=status.HTTP_200_OK)
        else:
            return Response({"details": "Invalid Username / Password"}, status=status.HTTP_400_BAD_REQUEST)


class AccountManagementViewSet(viewsets.ModelViewSet):
    # permission_classes = (IsAuthenticated,)
    queryset = models.User.objects.all().order_by('id')
    serializer_class = serializers.SystemUsersSerializer
    search_fields = ['id', ]

    def get_queryset(self):
        return []

    @action(methods=["POST"], detail=False, url_path="change-password", url_name="change-password")
    def change_password(self, request):
        authenticated_user = request.user
        payload = request.data

        # if not authenticated_user.id:
        #     authenticated_user = get_user_model().objects.get(username="admin3")

        serializer = serializers.PasswordChangeSerializer(
            data=payload, many=False)
        if serializer.is_valid():
            with transaction.atomic():
                new_password = payload['new_password']
                confirm_password = payload['confirm_password']
                current_password = payload['current_password']
                password_min_length = 8

                string_check= re.compile('[-@_!#$%^&*()<>?/\|}{~:]') 

                if(string_check.search(new_password) == None): 
                    return Response({'details':
                                     'Password Must contain a special character'},
                                    status=status.HTTP_400_BAD_REQUEST)

                if not any(char.isupper() for char in new_password):
                    return Response({'details':
                                     'Password must contain at least 1 uppercase letter'},
                                    status=status.HTTP_400_BAD_REQUEST)

                if len(new_password) < password_min_length:
                    return Response({'details':
                                     'Password Must be atleast 8 characters'},
                                    status=status.HTTP_400_BAD_REQUEST)

                if not any(char.isdigit() for char in new_password):
                    return Response({'details':
                                     'Password must contain at least 1 digit'},
                                    status=status.HTTP_400_BAD_REQUEST)
                                    
                if not any(char.isalpha() for char in new_password):
                    return Response({'details':
                                     'Password must contain at least 1 letter'},
                                    status=status.HTTP_400_BAD_REQUEST)
                try:
                    user_details = get_user_model().objects.get(id=authenticated_user.id)
                except (ValidationError, ObjectDoesNotExist):
                    return Response({'details': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)

                # check if new password matches current password
                encoded = user_details.password
                check_pass = check_password(new_password, encoded)
                if check_pass:
                    return Response({'details': 'New password should not be the same as old passwords'}, status=status.HTTP_400_BAD_REQUEST)


                if new_password != confirm_password:
                    return Response({"details": "Passwords Do Not Match"}, status=status.HTTP_400_BAD_REQUEST)
                is_current_password = authenticated_user.check_password(
                    current_password)
                if is_current_password is False:
                    return Response({"details": "Invalid Current Password"}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    user_util.log_account_activity(
                        authenticated_user, user_details, "Password Change", "Password Change Executed")
                    existing_password = authenticated_user.password
                    user_details.is_defaultpassword = False
                    new_password_hash = make_password(new_password)
                    user_details.password = new_password_hash
                    user_details.last_password_reset = datetime.now()
                    user_details.save()
                    return Response("Password Changed Successfully", status=status.HTTP_200_OK)
        else:
            return Response({"details": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


    @action(methods=["GET"], detail=False, url_path="list-users-with-role", url_name="list-users-with-role")
    def list_users_with_role(self, request):
        authenticated_user = request.user
        role_name = request.query_params.get('role_name')
        if role_name is None:
            return Response({'details': 'Role is Required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            role = Group.objects.get(name=role_name)
        except (ValidationError, ObjectDoesNotExist):
            return Response({'details': 'Role does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        selected_users = get_user_model().objects.filter(groups__name=role.name)
        user_info = serializers.UsersSerializer(selected_users, many=True)
        return Response(user_info.data, status=status.HTTP_200_OK)


    @action(methods=["GET"], detail=False, url_path="get-account-activity", url_name="get-account-activity")
    def get_account_activity(self, request):
        authenticated_user = request.user
        account_id = request.query_params.get('account_id')
        if account_id is None:
            return Response({'details': 'Account ID is Required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            account_instance = get_user_model().objects.get(id=account_id)
        except (ValidationError, ObjectDoesNotExist):
            return Response({'details': 'Account does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        selected_records = []
        if hasattr(account_instance, 'user_account_activity'):
            selected_records = account_instance.user_account_activity.all()
        user_info = serializers.AccountActivitySerializer(
            selected_records, many=True)
        return Response(user_info.data, status=status.HTTP_200_OK)


    @action(methods=["GET"], detail=False, url_path="get-account-activity-detail", url_name="get-account-activity-detail")
    def get_account_activity_detail(self, request):
        authenticated_user = request.user
        request_id = request.query_params.get('request_id')
        if request_id is None:
            return Response({'details': 'Request ID is Required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            account_activity_instance = models.AccountActivity.objects.get(
                id=request_id)
        except (ValidationError, ObjectDoesNotExist):
            return Response({'details': 'Request does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        account_info = serializers.AccountActivityDetailSerializer(
            account_activity_instance, many=False)
        return Response(account_info.data, status=status.HTTP_200_OK)


    @action(methods=["GET"], detail=False, url_path="list-roles", url_name="list-roles")
    def list_roles(self, request):
        authenticated_user = request.user
        role = Group.objects.all()
        record_info = serializers.RoleSerializer(role, many=True)
        return Response(record_info.data, status=status.HTTP_200_OK)


    @action(methods=["GET"], detail=False, url_path="list-user-roles", url_name="list-user-roles")
    def list_user_roles(self, request):
        authenticated_user = request.user
        role = user_util.fetchusergroups(authenticated_user.id)
        rolename = {
            "group_name": role
        }
        return Response(rolename, status=status.HTTP_200_OK)


    @action(methods=["GET"], detail=False, url_path="get-user-details", url_name="get-user-details")
    def get_user_details(self, request):
        authenticated_user = request.user
        user_id = request.query_params.get('user_id')
        if user_id is None:
            return Response({'details': 'Invalid Filter Criteria'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user_details = get_user_model().objects.get(id=user_id)
        except (ValidationError, ObjectDoesNotExist):
            return Response({'details': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        user_info = serializers.UsersSerializer(user_details, many=False)
        return Response(user_info.data, status=status.HTTP_200_OK)


    @action(methods=["GET"], detail=False, url_path="filter-by-username", url_name="filter-by-username")
    def filter_by_username(self, request):
        authenticated_user = request.user
        username = request.query_params.get('username')
        if username is None:
            return Response({'details': 'Invalid Filter Criteria'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user_details = get_user_model().objects.filter(username__contains=username)
        except (ValidationError, ObjectDoesNotExist):
            return Response({'details': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        user_info = serializers.UsersSerializer(user_details, many=True)
        return Response(user_info.data, status=status.HTTP_200_OK)


    @action(methods=["GET"], detail=False, url_path="get-profile-details", url_name="get-profile-details")
    def get_profile_details(self, request):
        authenticated_user = request.user
        payload = request.data
        try:
            user_details = get_user_model().objects.get(id=authenticated_user.id)
        except (ValidationError, ObjectDoesNotExist):
            return Response({'details': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        user_info = serializers.UsersSerializer(user_details, many=False)
        return Response(user_info.data, status=status.HTTP_200_OK)


# class DeparmentViewSet(viewsets.ModelViewSet):
#     # permission_classes = (IsAuthenticated,)
#     queryset = models.Department.objects.all().order_by('id')
#     serializer_class = serializers.DepartmentSerializer
#     search_fields = ['name', ]

#     def get_queryset(self):
#         all_departments = models.Department.objects.all()
#         return all_departments


class ICTSupportViewSet(viewsets.ModelViewSet):
    # permission_classes = (IsAuthenticated,)
    queryset = models.User.objects.all().order_by('id')
    serializer_class = serializers.SystemUsersSerializer
    search_fields = ['id', ]

    def get_queryset(self):
        return []

    @action(methods=["POST"], detail=False, url_path="reset-user-password",url_name="reset-user-password")
    def reset_user_password(self, request):
        authenticated_user = request.user
        payload = request.data
        serializer = serializers.UserIdSerializer(data=payload, many=False)
        if serializer.is_valid():
            with transaction.atomic():
                userid = payload['user_id']
                try:
                    user_details = get_user_model().objects.get(id=userid)
                except (ValidationError, ObjectDoesNotExist):
                    return Response({'details': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)
                new_password = str(user_details.username)
                hashed_password = make_password(new_password)
                user_details.password = hashed_password
                user_details.is_defaultpassword = True
                user_details.save()
                user_util.log_account_activity(
                    authenticated_user, user_details, "Password Reset", "Password Reset Executed")
                return Response("Password Reset Successful", status=status.HTTP_200_OK)
        else:
            return Response({"details": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


    @action(methods=["POST"], detail=False, url_path="swap-user-department", url_name="swap-user-department")
    def swap_user_department(self, request):
        authenticated_user = request.user
        payload = request.data
        serializer = serializers.SwapUserDepartmentSerializer(
            data=payload, many=False)
        if serializer.is_valid():
            with transaction.atomic():
                department_id = payload['department_id']
                user_id = payload['user_id']
                try:
                    user_details = get_user_model().objects.get(id=user_id)
                except (ValidationError, ObjectDoesNotExist):
                    return Response({'details': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)
                try:
                    department_details = models.Department.objects.get(
                        id=department_id)
                except (ValidationError, ObjectDoesNotExist):
                    return Response({'details': 'Department does not exist'}, status=status.HTTP_400_BAD_REQUEST)
                user_details.department = department_details
                user_details.save()
                user_util.log_account_activity(
                    authenticated_user, user_details, "Department Swap", "Department Was Swapped")
                return Response("Department Successfully Changed", status=status.HTTP_200_OK)
        else:
            return Response({"details": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


    @action(methods=["GET"], detail=False, url_path="user-registration-form", url_name="user-registration-form")
    def user_registration_form(self, request):
        payload = request.data
        user_registration_form = [{
            "type": "input",
            "label": "Username",
            "inputType": "text",
            "name": "name",
            "width": 6,
            "validations": [{
                "name": "required",
                "validator": "Validators.required",
                "message": "Name Required"
            },
                {
                "name": "pattern",
                "validator": "Validators.pattern('^[a-zA-Z]+$')",
                "message": "Accept only text"
            }
            ]
        },

            {
            "type": "select",
            "label": "Country",
            "name": "country",
            "width": 6,
            "options": [{
                "name": "Kenya",
                "id": "2"
            }, {
                "name": "Uganda",
                "id": "1"
            }]
        },
            {
            "type": "button",
            "width": 6,
            "label": "Save"
        }
        ]
        return Response(user_registration_form, status=status.HTTP_200_OK)

    @action(methods=["POST"], detail=False, url_path="edit-user",url_name="edit-user")
    def edit_user(self, request):
        payload = request.data
        serializer = serializers.EditUserSerializer(data=payload, many=False)
        if serializer.is_valid():
            id_number = payload['id_number']
            first_name = payload['first_name']
            last_name = payload['last_name']
            account_id = payload['account_id']
            try:
                new_id_number = int(id_number)
            except (ValidationError, ValueError):
                return Response({"details": "Invalid ID Number"},
                                status=status.HTTP_400_BAD_REQUEST)
            try:
                record_instance = get_user_model().objects.get(id=account_id)
            except (ValidationError, ObjectDoesNotExist):
                return Response(
                    {'details': 'User does not exist'},
                    status=status.HTTP_400_BAD_REQUEST)
            record_instance.first_name = first_name
            record_instance.last_name = last_name
            record_instance.id_number = new_id_number
            record_instance.save()
            return Response("Successfully Updated",
                            status=status.HTTP_200_OK)

        else:
            return Response({"details": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=["POST"],
            detail=False,
            url_path="award-role",
            url_name="award-role")
    def award_role(self, request):
        payload = request.data
        authenticated_user = request.user
        serializer = serializers.ManageRoleSerializer(data=payload, many=False)
        if serializer.is_valid():
            role_id = payload['role_id']
            account_id = payload['account_id']
            if not role_id:
                return Response(
                    {'details': 'Select atleast one role'},
                    status=status.HTTP_400_BAD_REQUEST)

            try:
                record_instance = get_user_model().objects.get(id=account_id)
            except (ValidationError, ObjectDoesNotExist):
                return Response(
                    {'details': 'Invalid User'},
                    status=status.HTTP_400_BAD_REQUEST)
            group_names = []
            for assigned_role in role_id:
                group = Group.objects.get(id=assigned_role)
                group_names.append(group.name)

                record_instance.groups.add(group)
            # user_util.log_account_activity(
            #     authenticated_user, record_instance, "Role Assignment",
            #     "USER ASSIGNED ROLES {{i}}".format(group_names))
            return Response("Successfully Updated",
                            status=status.HTTP_200_OK)

        else:
            return Response({"details": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    @action(methods=["POST"],
            detail=False,
            url_path="revoke-role",
            url_name="revoke-role")
    def revoke_role(self, request):
        payload = request.data
        authenticated_user = request.user
        serializer = serializers.ManageRoleSerializer(data=payload, many=False)
        if serializer.is_valid():
            role_id = payload['role_id']
            account_id = payload['account_id']
            if not role_id:
                return Response(
                    {'details': 'Select atleast one role'},
                    status=status.HTTP_400_BAD_REQUEST)

            try:
                record_instance = get_user_model().objects.get(id=account_id)
            except (ValidationError, ObjectDoesNotExist):
                return Response(
                    {'details': 'Invalid User'},
                    status=status.HTTP_400_BAD_REQUEST)
            group_names = []
            for assigned_role in role_id:
                group = Group.objects.get(id=assigned_role)
                group_names.append(group.name)
                record_instance.groups.remove(group)
            user_util.log_account_activity(
                authenticated_user, record_instance, "Role Revokation",
                "USER REVOKED ROLES {{i}}".format(group_names))
            return Response("Successfully Updated",
                            status=status.HTTP_200_OK)

        else:
            return Response({"details": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    def password_generator(self):
        # generate password
        lower = "abcdefghijklmnopqrstuvwxyz"
        upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        numbers = "0123456789"
        symbols = "[}{$@]!?"

        sample_lower = random.sample(lower,2)
        sample_upper = random.sample(upper,2)
        sample_numbers = random.sample(numbers,2)
        sample_symbols = random.sample(symbols,2)

        all = sample_lower + sample_upper + sample_numbers + sample_symbols

        random.shuffle(all)

        password = "".join(all)
        # print(password)
        # end generate password
        return password

    @action(methods=["POST"], detail=False, url_path="create-user", url_name="create-user")
    def create_user(self, request):
        payload = request.data
        authenticated_user = request.user

        if not authenticated_user.id:
            authenticated_user = get_user_model().objects.get(username="kings")

        serializer = serializers.CreateUserSerializer(data=payload, many=False)
        if serializer.is_valid():
            with transaction.atomic():
                id_number = payload['id_number']
                username = payload['username']
                first_name = payload['first_name']
                last_name = payload['last_name']
                department_id = payload['department_id']
                role_name = payload['role_name']
                registry = payload['registry']
                userexists = get_user_model().objects.filter(username=username).exists()
                idexists = get_user_model().objects.filter(id_number=id_number).exists()
                is_applicant = False
                is_department_admin = False
                is_approver = False
                is_business_analyst = False

                if idexists or userexists:
                    return Response({'details': 'User With Credentials Already Exist'}, status=status.HTTP_400_BAD_REQUEST)
                # try:
                #     department_details = models.Department.objects.get(
                #         id=department_id)
                # except (ValidationError, ObjectDoesNotExist):
                #     return Response({'details': 'Department does not exist'}, status=status.HTTP_400_BAD_REQUEST)
                try:
                    group_details = Group.objects.get(id=role_name)
                except (ValidationError, ObjectDoesNotExist):
                    return Response({'details': 'Role does not exist'}, status=status.HTTP_400_BAD_REQUEST)
                if group_details.name == "DATA_CLERK":
                    is_applicant = True
                elif group_details.name == "DATA_ANALYST":
                    is_approver = True
                elif group_details.name == "DATA_DEPARTMENT_HEAD":
                    is_department_admin = True
                elif group_details.name == "BUSINESS_ANALYST":
                    is_business_analyst = True
                # hashed_pwd = make_password(id_number)
                # dummy_password = "clerk123"

                password = self.password_generator()
                # print("line 528",password)

                hashed_pwd = make_password(password)
                newuser = {
                    "username": username,
                    "id_number": id_number,
                    "first_name": first_name,
                    "last_name": last_name,
                    # "department": department_details,
                    "department": department_id,
                    "registry": registry,
                    "is_active": True,
                    "is_superuser": False,
                    "is_staff": False,
                    # "is_defaultpassword": True,
                    "is_defaultpassword": False,
                    "is_applicant": is_applicant,
                    "is_department_admin": is_department_admin,
                    "is_approver": is_approver,
                    "is_business_analyst": is_business_analyst,
                    "is_suspended": False,
                    "password": hashed_pwd,
                }
                create_user = get_user_model().objects.create(**newuser)
                group_details.user_set.add(create_user)
                user_util.log_account_activity(
                    authenticated_user, create_user, "Account Creation",
                    "USER CREATED")
                info = {
                    'success': 'User Created Successfully',
                    'password': password
                }
                return Response(info, status=status.HTTP_200_OK)

        else:
            return Response({"details": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=["POST"], detail=False, url_path="suspend-user", url_name="suspend-user")
    def suspend_user(self, request):
        authenticated_user = request.user
        payload = request.data
        serializer = serializers.SuspendUserSerializer(
            data=payload, many=False)
        if serializer.is_valid():
            with transaction.atomic():
                user_id = payload['user_id']
                remarks = payload['remarks']
                try:
                    user_details = get_user_model().objects.get(id=user_id)
                except (ValidationError, ObjectDoesNotExist):
                    return Response({'details': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)

                user_details.is_suspended = True
                user_util.log_account_activity(
                    authenticated_user, user_details, "Account Suspended", remarks)
                user_details.save()
                return Response("Account Successfully Changed", status=status.HTTP_200_OK)
        else:
            return Response({"details": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=["POST"], detail=False, url_path="un-suspend-user", url_name="un-suspend-user")
    def un_suspend_user(self, request):
        authenticated_user = request.user
        payload = request.data
        serializer = serializers.SuspendUserSerializer(
            data=payload, many=False)
        if serializer.is_valid():
            user_id = payload['user_id']
            remarks = payload['remarks']
            with transaction.atomic():
                try:
                    user_details = get_user_model().objects.get(id=user_id)
                except (ValidationError, ObjectDoesNotExist):
                    return Response({'details': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)

                user_details.is_suspended = False
                user_util.log_account_activity(
                    authenticated_user, user_details, "Account UnSuspended", remarks)
                user_details.save()
                return Response("Account Unsuspended", status=status.HTTP_200_OK)
        else:
            return Response({"details": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
