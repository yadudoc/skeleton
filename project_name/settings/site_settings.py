from os import environ

environ["SECRET_KEY"]="<DJANGOSECRETKEY>"
DATABASES = {
	'default': {
		'ENGINE':'django.db.backends.mysql',
        'NAME': '<DBNAME>',
        'USER': '<DBUSER>',
        'PASSWORD': '<DBPASS>',
        'HOST': '<DBHOST>',
        'PORT': '<DBPORT>',
	}
}