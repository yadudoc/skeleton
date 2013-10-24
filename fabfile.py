from fabric.api import *
from fabric.colors import *
import time

def install_package(name):
    """ install a package using APT """
    with settings(hide('running', 'stdout'), warn_only=True):
        print yellow('Installing package %s... ' % name),
        sudo('apt-get -qq -y --force-yes install %s' % name)
        print green('[DONE]')
        
def update_apt():
    """ run apt-get update """
    with settings(hide('running', 'stdout'), warn_only=True):
        print yellow('Updating APT cache... '),
        sudo('apt-get update')
        print green('[DONE]')

def collect():
    env.release = time.strftime('%Y%m%d%H%M%S')
    local("find . -name '*.pyc' -print0|xargs -0 rm", capture=False)

    #local('python ./{{project_name}}/manage.py collectstatic --settings={{project_name}}.settings.init_deploy  --noinput ')
    #local('python ./{{project_name}}/manage.py compress --settings={{project_name}}.settings.init_deploy ')
    local('python ./{{project_name}}/manage.py collectstatic --noinput ')
    local('tar -czf  %(release)s.tar.gz --exclude=.git --exclude={{project_name}}/media *' % env)

def upload_tar_from_git():
    require('release', provided_by=[deploy, setup])
    "Create an archive from the current Git master branch and upload it"
    #local('git archive --format=tar master | gzip > %(release)s.tar.gz' % env)
    # local('tar -czf  %(release)s.tar.gz --exclude=.git --exclude=expacore/media *' % env)
    run('mkdir -p %(path)s/releases/%(release)s' % env )
    put('%(release)s.tar.gz' % env, '%(path)s/packages/' % env)
    run('cd %(path)s/releases/%(release)s && tar zxf ../../packages/%(release)s.tar.gz' % env)
    sudo('rm %(path)s/packages/%(release)s.tar.gz' % env)
    # local('rm %(release)s.tar.gz' % env)

def install_requirements():
    "Install the required packages from the requirements file using pip"
    # NOTE ... django requires a global install for some reason
    require('release', provided_by=[deploy, setup])
    with cd('%(path)s' % env):
        # NOTE - there is a weird ass bug with distribute==8 that blows up all setup.py develop installs for eggs from git repos
        run('./bin/pip install --upgrade distribute==0.6.28')
        # run('./bin/pip install --upgrade versiontools')
        
        run('./bin/pip install -r ./releases/%(release)s/requirements/%(requirements_file)s.txt' % env)

def symlink_current_release():
    "Symlink our current release"
    require('release', provided_by=[deploy, setup])
    run('cd %(path)s; rm releases/previous; mv releases/current releases/previous;' % env)
    run('cd %(path)s; ln -s %(release)s releases/current' % env)
    #run('cd %(path)s/releases/current/expacore/media; cp -r %(path)s/lib/python2.7/site-packages/django/contrib/admin/static/admin ./admin' % env)

def migrate():
    "Update the database"
    require('project_name')
    require('init_file')
    with cd('%(path)s/releases/current/{{project_name}}' % env):
        run('cp settings/%(init_file)s.py settings/__init__.py' % env)
        run('../../../bin/python manage.py syncdb --noinput')
        run('../../../bin/python manage.py migrate')
        #run('../../../bin/python manage.py loaddata app/fixtures/')

# Start/Stop Stuff
def start_webservers():
    sudo('/etc/init.d/nginx start')
    sudo('/etc/init.d/uwsgi start')


def restart_webserver():
    "Restart the web server"
    sudo('cp /usr/local/expacore/releases/current/conf/uwsgi.xml /etc/uwsgi.xml')
    sudo('/etc/init.d/uwsgi reload')
    #sudo('/etc/init.d/celeryd restart')

def install_web():
    sudo('mkdir -p %(path)s/tmp/' %env)
    sudo('mkdir -p %(path)s/pid/' %env)
    sudo('mkdir -p %(path)s/sock/'%env)

    #sudo('apt-get -y --force-yes install nginx')
    install_package('nginx')
    put('./deploy/{{project_name}}.key', '/etc/ssl/private/', use_sudo=True)
    put('./deploy/{{project_name}}.crt', '/etc/ssl/certs/', use_sudo=True)
    sudo('chown 700 /etc/ssl/private/{{project_name}}.key /etc/ssl/certs/{{project_name}}.crt')
    # install_nginx_custom()
    sudo('pip install uwsgi')
    put('./deploy/uwsgi /etc/init.d/uwsgi', use_sudo=True)
    put('./deploy/uwsgi.xml /etc/uwsgi.xml', use_sudo=True)
    put('./deploy/nginx.conf /etc/nginx/nginx.conf', use_sudo=True)
    sudo('chmod 755 /etc/init.d/uwsgi')
    start_webservers()

def install_base():
    """
    Set up all the basic packages that are required, except for database
    TODO: read packages from file
    """
    #require('hosts', provided_by=[local,production,start_instance])
    require('path')
    update_apt()
    install_package('aptitude')
    install_package('ntpdate')
    install_package('python-setuptools')
    install_package('gcc')
    install_package('git-core')
    install_package('libxml2-dev')
    install_package('libxslt1-dev')
    install_package('python-virtualenv')

    install_package('python-dev')
    install_package('python-lxml')
    install_package('libcairo2')
    install_package('libpango1.0-0')
    install_package('libgdk-pixbuf2.0-0')
    install_package('libffi-dev')

def setup_mysql_client():
    """
    Setup mysql drivers
    """
    install_package('mysql-client')
    install_package('libmysqlclient-dev')

    sudo('aptitude -y build-dep python-mysqldb')

    install_package('python-mysqldb')

def setup_mysql_server():
    install_package('mysql-server')
    sudo('mysqladmin create {{project_name}}')
    sudo('mysql -uroot -e "GRANT ALL PRIVILEGES ON {{project_name}}.* to {{project_name}}@localhost IDENTIFIED BY "{{project_name}}"')

def setup_base():
    """
    take a fresh instance and create a working webserver
    """
    require('path')
    update_apt()

    install_base()
    setup_mysql_client()
    setup_mysql_server()
    sudo('mkdir -p %(path)s/packages; cd %(path)s; virtualenv --distribute .;'%env)

def setup_prod():
    sudo('cd %(path)s; mkdir -p releases; mkdir -p shared; mkdir -p packages; touch releases/previous; touch releases/current' %env)
    sudo ('chown -R %(user)s:%(user)s %(path)s'%env)

    upload_tar_from_git()
    install_requirements()
    symlink_current_release()
    migrate()

    install_web()

def setup_dev():
    install_requirements()

def dev():
    env.projectname = '{{project_name}}'
    env.path = '/mnt/ym/%(projectname)s' %env
    env.user = 'vagrant'
    #env.target="dev"
    #env.init_file = '__init__development'
    #env.requirements_file = 'requirements_prod'
    #env.virtualhost_path = "/"
    #env.security_group = 'dev'
    sudo('aptitude reinstall ca-certificates')
    setup_base()
    setup_dev()

