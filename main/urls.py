from django.contrib import admin
from django.urls import path, include
from django.conf.urls.static import static
from django.conf import settings

API_VERSION = 'api/v3/'

urlpatterns = [
    # path('admin/', admin.site.urls),
    path(API_VERSION, include('user_manager.urls')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

if settings.DEBUG:
    adminurl = [
        path('admin/', admin.site.urls),
    ]
    urlpatterns += adminurl
