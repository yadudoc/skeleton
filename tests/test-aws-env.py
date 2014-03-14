import os, sys, tempfile, urllib2, sys
from fabric.api import env, local, lcd, prefix
from fabric.colors import red, green
from contextlib import contextmanager

test_root = '~/tmp'
test_root = os.path.expanduser(test_root)
test_root = os.path.expandvars(test_root)
project_name = 'testproject'
config_dir = '~/tmp/configs'
config_dir = os.path.expanduser(config_dir)
config_dir = os.path.expandvars(config_dir)
rcp = 'rsync -a --partial --progress '
smallstack = """fab create_ec2:expatest-small-1 \
                    bootstrap:expatest-small-1,core \
                    bootstrap:expatest-small-1,gis \
                    bootstrap:expatest-small-1,blog \
                    deployapp:expatest-small-1,core \
                    deployapp:expatest-small-1,gis \
                    deployapp:expatest-small-1,app \
                    deploywp:expatest-small-1"""

fullstack = """fab create_rds:expacore-db-1,core,postgres \
                   create_rds:expagis-db-1,gis,postgres \
                   create_rds:expablog-db-1,blog,mysql \
                   create_rds:expatest-db-1,app,postgres \
                   create_ec2:expacore-full-1 \
                   create_ec2:expagis-full-1 \
                   create_ec2:expatest-full-1 \
                   bootstrap:expacore-full-1,core \
                   bootstrap:expacore-full-1,blog \
                   bootstrap:expagis-full-1,gis \
                   bootstrap:expatest-full-1,app \
                   deployapp:expacore-full-1,core \
                   deployapp:expagis-full-1,gis \
                   deploywp:expacore-full-1 \
                   deployapp:expatest-full-1,app"""

#----------HELPER FUNCTIONS-----------


@contextmanager
def virtualenv(directory):
    env.activate = 'source %s/bin/activate' % directory
    with lcd(envdir):
        with prefix(env.activate):
            yield
#--------------------------------------

# Setup virtual env
if len(sys.argv) == 2:
    envdir = sys.argv[1]
else:
    envdir = tempfile.mkdtemp(prefix=project_name + '.', dir=test_root)

try:
    os.mkdir(test_root)
except OSError:
    pass

# Cleanup previous settings files
#local('rm ./*_settings.json')

print "creating venv %s..." % envdir
local('virtualenv %s' % envdir)
with lcd(envdir):
    with virtualenv(envdir):
        local('pip install -q django==1.6')
        local('django-admin.py startproject --template=https://github.com/expa/skeleton/archive/master.zip --extension=py,rst,html,conf,xml --name=Vagrantfile --name=crontab %s' % project_name)
        with lcd(project_name):
            local(rcp + config_dir + '/*.cfg ' + config_dir + '/keys ' + ' ./ ')
            local('pip install -q -r requirements/local.txt')
            local(smallstack)

# test urls
urls = ['https://core.test.expa.com', 'https://gis.test.expa.com', 'https://www.test.expa.com', 'https://test.expa.com', 'http://blog.test.expa.com']
url_response = dict.fromkeys(urls)
for url in urls:
    try:
        response = urllib2.urlopen(url)
        url_response[url] = response.code
        print url + ": " + green(str(response.code))
    except urllib2.HTTPError, error:
        print url + ": " + red(error.code)
    except urllib2.URLError, error:
        print url + ": " + red(error.args)

try:
    type(error)
    print('fail')
    sys.exit(1)
except NameError:
    if range(401, 600) in url_response.values():
        print('fail')
        sys.exit(1)

print('pass')
