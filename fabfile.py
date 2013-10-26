import time
import boto
import boto.ec2
import boto.rds

from fabric.api import *
from fabric.colors import *


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

def create_ec2_securityGroup(name,description,ruleSet):
    conn = boto.connect_ec2()
    if name not in [sg.name for sg in conn.get_all_security_groups()]:
        print green('Creating EC2 security group "%s"') %name
        try:
            conn.create_security_group(name,description)
            for protocol, port, cidr in ruleSet:
                conn.authorize_security_group(group_name=name,ip_protocol=protocol,from_port=port,to_port=port,cidr_ip=cidr)
        except Exception as error:
            print red('Error occured while create security group "%s": %s') %(name, str(error))
            print yellow('Rolling back!')
            conn.delete_security_group(name)
            return
    else:
        print green('Security group "%s" already created. continuing') %name

def create_rds_securityGroup(name,description,ec2SecurityGroupName):
    rdsConn = boto.rds.connect_to_region('us-east-1')
    ec2Conn = boto.connect_ec2()
    ec2SecurityGroups = ec2Conn.get_all_security_groups()
    ec2SecurityGroup = [ ec2sg for ec2sg in ec2SecurityGroups if ec2sg.name == name ]
    if name not in [sg.name for sg in rdsConn.get_all_dbsecurity_groups()]:
        print green('Creating RDS security group "%s"') %name
        try:
            dbSecurityGroup = rdsConn.create_dbsecurity_group(name,description)
            dbSecurityGroup.authorize(ec2_group=ec2SecurityGroup[0])
        except Exception as error:
            print red('Error occured while create security group "%s": %s') %(name, str(error))
            print yellow('Rolling back!')
            rdsConn.delete_dbsecurity_group(name)
            return   

# Instance Initiation
amis = {'t1.micro' : 'ami-137bcf7a',
        'm1.small' : 'ami-2efa9d47',
        'm1.large' : 'ami-121da47b' }

def start_ec2_instance(inst_size, ami=None, key='default', zone='us-east-1b'):
    """ start an instance """
    if inst_size not in amis:
        print red('You need to supply instance size: %s' % ' '.join(amis.keys()))
        return

    if not ami:
        ami = amis[inst_size]
        
    conn = boto.connect_ec2()

    try:
        reservation = conn.run_instances(ami, instance_type=inst_size, key_name=key, placement=zone,security_groups=[env.ec2SecurityGroupName])
    except Exception as error:
        print red('Error occured while starting the instance %s' % str(error))
        return 

    instance = reservation.instances[0]
    print green('Waiting for instance to start...')
    status = instance.update()
    while status != "running":
        time.sleep(10)
        status = instance.update()

        if status == 'running':
            print green('New instance "' + instance.id + '" accessible at ' + instance.public_dns_name)

    env.disable_known_hosts = True
    env.host_string = str(instance.public_dns_name)
    env.hosts = [env.host_string,]

def new_rds(dbInstanceId, appName, dbStorageSize, dbInstanceSize, dbUser, dbPassword):
    conn = boto.rds.connect_to_region('us-east-1')
    try:
        db = conn.create_dbinstance(id=dbInstanceId, allocated_storage=dbStorageSize, instance_class=dbInstanceSize, engine='MySQL', master_username=dbUser, master_password=dbPassword, db_name=appName, security_groups=[env.rdsSecurityGroupName])
    except Exception as error:
        print red('Error occured while provisioning the RDS instance %s' % str(error))
        return

    print green('Waiting for rdsInstance to start...')
    status = db.update()
    while status != 'available':
        time.sleep(45)
        status = db.update()
        print yellow('Still waiting for rdsInstance to start. current status is ') + red(status)

    if status == 'available':
        print green('New rdsInstance %s accessible at %s on port %d') % (db.id, db.endpoint[0], db.endpoint[1])

    env.dbHostString = str(db.endpoint[0])
    env.dbPortString = str(db.endpoint[1])
    env.dbHost = [env.dbHostString]
    env.dbPort = [env.dbPortString]

def new_webserver():
    """ start a large instance using our custom AMI and do the rest of the setup """
    start_ec2_instance('m1.small', key='test')
    # wait a bit
    time.sleep(20)
    sudo('aptitude reinstall ca-certificates')
    
def install_web():
    sudo('mkdir -p %(path)s/tmp/' %env)
    sudo('mkdir -p %(path)s/pid/' %env)
    sudo('mkdir -p %(path)s/sock/'%env)

    #sudo('apt-get -y --force-yes install nginx')
    install_package('nginx')
    put('./config/{{project_name}}.key', '/etc/ssl/private/', use_sudo=True)
    put('./config/{{project_name}}.crt', '/etc/ssl/certs/', use_sudo=True)
    sudo('chown 700 /etc/ssl/private/{{project_name}}.key /etc/ssl/certs/{{project_name}}.crt')
    # install_nginx_custom()
    sudo('pip install uwsgi')
    put('./config/uwsgi /etc/init.d/uwsgi', use_sudo=True)
    put('./config/uwsgi.xml /etc/uwsgi.xml', use_sudo=True)
    put('./config/nginx.conf /etc/nginx/nginx.conf', use_sudo=True)
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
    install_package('debconf-utils')
    sudo('echo mysql-server-5.5 mysql-server/root_password password mysql | debconf-set-selections', quiet=True)
    sudo('echo mysql-server-5.5 mysql-server/root_password_again password mysql | debconf-set-selections', quiet=True)
    sudo('echo mysql-server-5.5 mysql-server/root_password seen true | debconf-set-selections', quiet=True)
    sudo('echo mysql-server-5.5 mysql-server/root_password_again seen true | debconf-set-selections', quiet=True)

    install_package('mysql-server-5.5')
    sudo('mysqladmin -pmysql create {{project_name}}', warn_only=True)
    sudo('mysql -uroot -pmysql -e "GRANT ALL PRIVILEGES ON {{project_name}}.* to {{project_name}}@\'localhost\' IDENTIFIED BY \'{{project_name}}\'"')

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

def collect():
    env.release = time.strftime('%Y%m%d%H%M%S')
    local("find . -name '*.pyc' -print0|xargs -0 rm", capture=False)

    #local('python ./{{project_name}}/manage.py collectstatic --settings={{project_name}}.settings.init_deploy  --noinput ')
    #local('python ./{{project_name}}/manage.py compress --settings={{project_name}}.settings.init_deploy ')
    local('python ./{{project_name}}/manage.py collectstatic --noinput ')
    local('tar -czf  %(release)s.tar.gz --exclude=.git --exclude={{project_name}}/media *' % env)

def upload_tar_from_git():
    require('release', provided_by=[collect])
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

def symlink_current_release():
    "Symlink our current release"
    require('release', provided_by=[collect])
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

def setup_prod():
    sudo('cd %(path)s; mkdir -p releases; mkdir -p shared; mkdir -p packages; touch releases/previous; touch releases/current' %env)

    upload_tar_from_git()
    install_requirements()
    symlink_current_release()
    migrate()

    install_web()

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
    
def setup_dev_aws():
    env.projectname = '{{project_name}}'
    env.path = '/mnt/ym/%(projectname)s' %env
    env.user = 'ubuntu'
    env.target="dev"
    env.init_file = '__init__development'
    env.requirements_file = 'local'
    env.ec2SecurityGroupName = 'webservers'
    env.ec2SecurityGroupDesc = 'front-ends'
    env.ec2SecurityGroupRuleSet = [ [ 'tcp', '22', '0.0.0.0/0'], ['tcp', '80', '0.0.0.0/0'], ['tcp', '443', '0.0.0.0/0'] ]
    env.rdsSecurityGroupName = 'webservers'
    env.rdsSecurityGroupDesc = 'front-ends'
    dbInstanceId = "dev-db-" + time.strftime('%Y%m%d%H%M%S')

    create_ec2_securityGroup(env.ec2SecurityGroupName, env.ec2SecurityGroupDesc, env.ec2SecurityGroupRuleSet)
    create_rds_securityGroup(env.rdsSecurityGroupName, env.rdsSecurityGroupDesc, env.ec2SecurityGroupName) 
    new_rds(dbInstanceId,dbInstanceSize='db.m1.small',dbUser='root',dbPassword='mysql',dbStorageSize='10',appName='{{project_name}}')
    new_webserver() 
    setup_base()

    install_requirements()    
