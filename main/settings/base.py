
import os
from dotenv import load_dotenv
load_dotenv()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SECRET_KEY = 'django-insecure-d#6)c+(ejj)8%xa=o)7h0$eh1_atz^d+^15$4o1qc9dz3&ipje'

ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'corsheaders',
    'rest_framework',
    'user_manager'
]


MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'main.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': ['templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.media',
            ],
        },
    },
]

WSGI_APPLICATION = 'main.wsgi.application'

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Africa/Nairobi'
USE_I18N = True
USE_L10N = True
USE_TZ = True
STATIC_URL = '/static/'


AUTH_USER_MODEL = 'user_manager.User'
LOGIN_REDIRECT_URL = '/portal'
LOGIN_URL = '/edms/login'



PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
STATIC_URL = '/static/'

if os.getenv('MAINMEDIA') != "NAS":
    MEDIA_ROOT = os.getenv('MEDIA_ROOT')
    MEDIA_URL = os.getenv('MEDIA_URL')



STATIC_PATH = os.path.join(PROJECT_ROOT, 'staticfiles')
STATICFILES_DIRS = (STATIC_PATH,)
STATIC_ROOT = os.path.join(BASE_DIR, 'static')


# App Schema Configurations
# USER_MANAGER_SCHEMA = 'system_users'

REST_FRAMEWORK = {
    # 'DEFAULT_AUTHENTICATION_CLASSES': (
    #     'authentication.backends.SystemApiAuthentication',
    # ),
    # 'DEFAULT_PERMISSION_CLASSES': (
    #     'rest_framework.permissions.IsAuthenticated',
    # )
}

X_FRAME_OPTIONS = 'ALLOW-FROM https://127.0.0.1/'


DATA_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024 * 8000  # 8Gb
FILE_UPLOAD_MAX_MEMORY_SIZE = DATA_UPLOAD_MAX_MEMORY_SIZE
CORS_ORIGIN_ALLOW_ALL = True
# TOKEN_EXPIRY = 7200

TOKEN_SECRET_CODE = 'edms2021?Refined'


CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'Authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
    'Access-Control-Allow-Origin',
]

MAINMEDIA = os.getenv('MAINMEDIA')

CUSTOM_PROTOCOL = 'http://'
API_VERSION = os.getenv('API_VERSION')
CONFIGURATION_MANAGER_IP = os.getenv('CONFIGURATION_MANAGER_IP')
DEPARTMENT_DETAIL_VIEW = CUSTOM_PROTOCOL+CONFIGURATION_MANAGER_IP+'/'+API_VERSION+'/'+'department/detail-view?request_id='


