import time
from fabric.operations import put
from fabric.api import *
from fabric.colors import green as _green, yellow as _yellow, red as _red
from fabric.context_managers import hide, show, lcd

@task
def setup_dev():
    env.projectname = '{{project_name}}'
    env.path = '/mnt/ym/%(projectname)s' %env
    env.user = 'vagrant'
    env.target="dev"
    env.init_file = '__init__development'
    env.requirements_file = 'local'

    setup_base()
    setup_mysql_server()
    install_requirements()

@task
def setup_base():
    """
    take a fresh instance and create a working webserver
    """
    require('path')
    update_apt()

    install_base()
    setup_mysql_client()
    sudo('mkdir -p %(path)s/packages; cd %(path)s; virtualenv --distribute .;'%env)
    sudo ('chown -R %(user)s:%(user)s %(path)s'%env)

@task
def setup_mysql_server():
    install_package('debconf-utils')
    sudo('echo mysql-server-5.5 mysql-server/root_password password mysql | debconf-set-selections', quiet=True)
    sudo('echo mysql-server-5.5 mysql-server/root_password_again password mysql | debconf-set-selections', quiet=True)
    sudo('echo mysql-server-5.5 mysql-server/root_password seen true | debconf-set-selections', quiet=True)
    sudo('echo mysql-server-5.5 mysql-server/root_password_again seen true | debconf-set-selections', quiet=True)

    install_package('mysql-server-5.5')
    sudo('mysqladmin -pmysql create {{project_name}}', warn_only=True)
    sudo('mysql -uroot -pmysql -e "GRANT ALL PRIVILEGES ON {{project_name}}.* to {{project_name}}@\'localhost\' IDENTIFIED BY \'{{project_name}}\'"')

@task
def setup_mysql_client():
    """
    Setup mysql drivers
    """
    install_package('mysql-client')
    install_package('libmysqlclient-dev')

    sudo('aptitude -y build-dep python-mysqldb')

    install_package('python-mysqldb')

@task
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

@task
def install_requirements():
    "Install the required packages from the requirements file using pip"
    # NOTE ... django requires a global install for some reason
    #require('release', provided_by=[collect])
    require('path')
    if 'release' not in env:
        env.release = 'current'

    print 'path is %(path)s' %env
    with cd('%(path)s' % env):
        # NOTE - there is a weird ass bug with distribute==8 that blows up all setup.py develop installs for eggs from git repos
        run('./bin/pip install --upgrade distribute==0.6.28')
        # run('./bin/pip install --upgrade versiontools')
        
        run('./bin/pip install -r ./releases/%(release)s/requirements/%(requirements_file)s.txt' % env)


#----------HELPER FUNCTIONS-----------
def install_package(name):
    """ install a package using APT """
    with settings(hide('running', 'stdout'), warn_only=True):
        print _yellow('Installing package %s... ' % name),
        sudo('apt-get -qq -y --force-yes install %s' % name)
        print _green('[DONE]')

def update_apt():
    """ run apt-get update """
    with settings(hide('running', 'stdout'), warn_only=True):
        print _yellow('Updating APT cache... '),
        sudo('apt-get update')
        print _green('[DONE]')
