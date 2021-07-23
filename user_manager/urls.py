from django.urls import path, include
from django.views.decorators.csrf import csrf_exempt
from rest_framework.routers import DefaultRouter
from user_manager import views

router = DefaultRouter(trailing_slash=False)

router.register('authentication',views.AuthenticationViewSet, basename='authentication')
router.register('account-management',views.AccountManagementViewSet, basename='account-management')
router.register('ict-support',views.ICTSupportViewSet, basename='ict-support')      
# router.register('department',views.DeparmentViewSet, basename='department')  
                         
urlpatterns = router.urls