import requests
from rest_framework import serializers
from django.contrib.auth import get_user_model
# from edms.models import DocumentActivity
from django.contrib.auth.models import Group
from django.conf import settings


class UserDetailSerializer(serializers.Serializer):
    username = serializers.CharField()
    id_number = serializers.CharField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()


class SystemUsersSerializer(serializers.Serializer):
    UserId = serializers.CharField()
    username = serializers.CharField()
    firstname = serializers.CharField()
    lastname = serializers.CharField()


class PasswordChangeSerializer(serializers.Serializer):
    new_password = serializers.CharField()
    confirm_password = serializers.CharField()
    current_password = serializers.CharField()


class GroupSerializer(serializers.Serializer):
    id = serializers.CharField()
    name = serializers.CharField()


class UserIdSerializer(serializers.Serializer):
    user_id = serializers.CharField()


class DepartmentSerializer(serializers.Serializer):
    id = serializers.CharField()
    name = serializers.CharField()
    keyword = serializers.CharField()


class UsersSerializer(serializers.ModelSerializer):
    id = serializers.CharField()
    username = serializers.CharField()
    id_number = serializers.CharField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    is_active = serializers.CharField()
    is_suspended = serializers.CharField()
    department = serializers.SerializerMethodField(read_only=True)
    user_groups = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = get_user_model()
        fields = [
            'id', 'username', 'id_number', 'first_name', 'last_name', 'is_active', 'is_suspended',
            'department', 'user_groups'
        ]

    def get_department(self, obj):
        # department_details = obj.department
        department_id = obj.department
        response = requests.get(settings.DEPARTMENT_DETAIL_VIEW + department_id)
        department_info = response.json()
        # if department_details is None:
        #     return {}
        # department_info = DepartmentSerializer(department_details, many=False)
        # return department_info.data
        return department_info

    def get_user_groups(self, obj):
        current_user = obj
        allgroups = Group.objects.filter(user=current_user)
        serializer = GroupSerializer(allgroups, many=True)
        return serializer.data


class SwapUserDepartmentSerializer(serializers.Serializer):
    user_id = serializers.CharField()
    department_id = serializers.CharField()


class RoleSerializer(serializers.Serializer):
    id = serializers.CharField()
    name = serializers.CharField()


class CreateUserSerializer(serializers.Serializer):
    username = serializers.CharField()
    id_number = serializers.CharField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    department_id = serializers.CharField()
    registry = serializers.CharField()
    role_name = serializers.CharField()


class SuspendUserSerializer(serializers.Serializer):
    user_id = serializers.CharField()
    remarks = serializers.CharField()


class AccountActivitySerializer(serializers.Serializer):
    id = serializers.CharField()
    activity = serializers.CharField()


# class AccountActivityDetailSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = DocumentActivity()
#         fields = '__all__'

class AccountActivityDetailSerializer(serializers.ModelSerializer):
    id = serializers.CharField()
    document = serializers.SerializerMethodField(read_only=True)
    user = serializers.SerializerMethodField(read_only=True)
    document_status= serializers.CharField()
    action_time = serializers.DateTimeField()

class EditUserSerializer(serializers.Serializer):
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    id_number = serializers.CharField()
    account_id = serializers.CharField()


class ManageRoleSerializer(serializers.Serializer):
    role_id = serializers.ListField(required=True)
    account_id = serializers.CharField()