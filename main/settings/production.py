from .base import *
if os.getenv('SERVER_DEBUG_MODE') == 'True':
    DEBUG = True
else:
    DEBUG = False

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': os.getenv('DBNAME'),
        'USER': os.environ.get('DBUSERNAME'),
        'PASSWORD': os.environ.get('DBPASSWORD'),
        'ATOMIC_REQUESTS': True,
        'OPTIONS': {
            'options': '-c search_path={}'.format(os.environ.get('DBSCHEMA'))
        },
        'HOST': str(os.environ.get('DBHOST')),
        'PORT': int(os.environ.get('DBPORT')),

    }
}

TOKEN_EXPIRY = int(os.getenv('TOKEN_EXPIRY_TIME'))

SMB_STORAGE_OPTIONS = {
    "host": os.getenv('SMB_HOST'),
    "username": os.getenv('SMB_USERNAME'),
    "password": os.getenv('SMB_PASSWORD'),
    "server_name": os.getenv('SMB_SERVER_NAME'),
    "share_name": os.getenv('SMB_SHARE_NAME'),
    "service_name": os.getenv('SMB_SERVICE_NAME'),
    "client_machine": os.getenv('SMB_CLIENT_MACHINE'),
    "file_path": "",
    "timeout": os.getenv('SMB_TIMEOUT'),
}


if os.getenv('OVER_RIDER') == 'True':
    OVER_RIDE_MODE = True
else:
    OVER_RIDE_MODE = False
