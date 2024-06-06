"""
Django settings for vulnerabilities project.

Generated by 'django-admin startproject' using Django 5.0.1.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

from pathlib import Path
import os
import project_secrets
import this_env

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent
THIS_ENVIRONMENT = os.environ['THIS_ENV'] # "PROD" or "TEST"


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

# SECURITY WARNING: don't run with debug turned on in production!
if THIS_ENVIRONMENT == "PROD":
    DEBUG = False
else:
    DEBUG = True


if THIS_ENVIRONMENT == "PROD":
    ALLOWED_HOSTS = ["https://vulnerabilities.oslo.kommune.no",]
    CSRF_TRUSTED_ORIGINS = ["https://vulnerabilities.oslo.kommune.no",]

if THIS_ENVIRONMENT == "TEST":
    ALLOWED_HOSTS = ['localhost',]


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'vulnapp'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'csp.middleware.CSPMiddleware',
]


# Security headers. CSP reqires "CSPMiddleware"
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = (
        "'self'",
        "'unsafe-inline'",
        "https://cdn.jsdelivr.net/npm/chart.js"
    )
CSP_FRAME_SRC = ("'self'",)
CSP_IMG_SRC = ("'self' data:")
CSP_STYLE_SRC = ("'unsafe-inline'", "'self'",)
CSP_INCLUDE_NONCE_IN = ['script-src']

SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True

CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = "Strict"

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_AGE = 57600  # 10 timer
SESSION_EXPIRE_AT_BROWSER_CLOSE = False




ROOT_URLCONF = 'vulnerabilities.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
                'templates',
                os.path.join(BASE_DIR, 'templates')
            ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'vulnerabilities.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

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


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'nb'

TIME_ZONE = 'Europe/Oslo'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

if THIS_ENVIRONMENT == "PROD":
    STATIC_URL = '/static/'
    STATIC_ROOT = os.path.join(BASE_DIR, "static/")
if THIS_ENVIRONMENT == "TEST":
    STATIC_URL = '/static/'
    STATICFILES_DIRS = [
        f"{BASE_DIR}/static/"
    ]


#MEDIA_URL = '/media/'
#MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
