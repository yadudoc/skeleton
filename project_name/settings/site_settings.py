from os import environ

environ["SECRET_KEY"] = "<DJANGOSECRETKEY>"
DATABASES = {
	'default': {
		#'ENGINE':'django.db.backends.mysql',
        'ENGINE':'django.db.backends.postgresql_psycopg2',		
        'NAME': '<DBNAME>',
        'USER': '<DBUSER>',
        'PASSWORD': '<DBPASS>',
        'HOST': '<DBHOST>',
        'PORT': '<DBPORT>',
	}
}
ALLOWED_HOSTS = [ '.' + '<DOMAIN_NAME>']
