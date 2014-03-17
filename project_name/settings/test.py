from base import *

# TEST SETTINGS
# TEST_RUNNER = 'discover_runner.DiscoverRunner'
TEST_DISCOVER_TOP_LEVEL = SITE_ROOT
TEST_DISCOVER_ROOT = SITE_ROOT
TEST_DISCOVER_PATTERN = "test_*.py"
# IN-MEMORY TEST DATABASE
# overwrite
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'skeleton_test',
        'USER': 'skeleton',
        'PASSWORD': 'skeleton',
        'HOST': "127.0.0.1",
        'PORT': 5432,
    }
}
