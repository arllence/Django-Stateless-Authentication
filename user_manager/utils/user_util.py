from django.contrib.auth.models import Group
from user_manager.models import AccountActivity, User
# from edms.models import DocumentActivity,DocumentUpload


def fetchusergroups(userid):
    userroles = []
    query_set = Group.objects.filter(user=userid)
    if query_set.count() >= 1:
        for groups in query_set:
            userroles.append(groups.name)
        return userroles
        
    else:
        return ""


def log_account_activity(actor, recipient, activity, remarks):
    create_activity = {
        "recipient": recipient,
        "actor": actor,
        "activity": activity,
        "remarks": remarks,

    }
    new_activity = AccountActivity.objects.create(**create_activity)


# def log_document_activity(document_instance, user_instance, activity):
#     # check whether the userid exists,check doc instance too
#     create_activity = {
#         "document": document_instance,
#         "user": user_instance,
#         "document_status": activity
#     }
#     create_log = DocumentActivity.objects.create(**create_activity)
