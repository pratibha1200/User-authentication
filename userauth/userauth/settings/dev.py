from .base import *

DEBUG = True
ALLOWED_HOSTS = ['*']
DEV = DEBUG

INSTALLED_APPS += ('debug_toolbar',)

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'userlog',
        'USER': 'postgres',
        'PASSWORD': 'postgres',
        'HOST': '',
        'PORT': '5432',
    }
}

MIDDLEWARE += ('debug_toolbar.middleware.DebugToolbarMiddleware',)

SECRET_KEY = 'devel'

EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

SITE_ID = 1

AUTH_PASSWORD_VALIDATORS = []

INTERNAL_IPS = ("127.0.0.1",)
