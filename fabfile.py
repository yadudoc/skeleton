import os, json, string, random
from tempfile import mkdtemp
from contextlib import contextmanager

from fabric.operations import put
from fabric.api import env, local, sudo, run, cd, prefix, task, settings, execute
from fabric.colors import green as _green, yellow as _yellow, red as _red
from fabric.context_managers import hide, show, lcd
import boto
import boto.ec2
import boto.rds
from config import Config
import time

# import configuration variables from untracked config file
try:
    aws_cfg = Config(open("aws.cfg"))
    env.key_filename = os.path.expanduser(os.path.join(aws_cfg["key_dir"],  
                                                       aws_cfg["key_name"] + ".pem"))
except Exception as e:
    print "aws.cfg not found. %s" %e

try:
    with open("settings.json", "r") as settingsFile:
        app_settings = json.load(settingsFile)
except Exception as e:
    app_settings = {"DATABASE_USER": "{{project_name}}",
                    "DATABASE_PASS": "{{project_name}}1234",
                    "APP_NAME": "{{project_name}}",
                    "DATABASE_NAME": "{{project_name}}",
                    "DATABASE_HOST": "",
                    "DATABASE_PORT": "",
                    "PROJECTPATH" : "/mnt/ym/{{project_name}}",
                    "REQUIREMENTSFILE" : "production",
                    "DJANGOSECRETKEY" : ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits + '!@#$%^&*()') for ii in range(64))}
    with open("settings.json", "w") as settingsFile:
        settingsFile.write(json.dumps(app_settings))

#-----FABRIC TASKS-----------

@task
def setup_aws_account():

    ec2 = connect_to_ec2()

    # Check to see if specified keypair already exists.
    # If we get an InvalidKeyPair.NotFound error back from EC2,
    # it means that it doesn't exist and we need to create it.
    try:
        key_name = aws_cfg["key_name"]
        key = ec2.get_all_key_pairs(keynames=[key_name])[0]
        print "key name {} already exists".format(key_name)
    except ec2.ResponseError, e:
        if e.code == 'InvalidKeyPair.NotFound':
            print 'Creating keypair: %s' % aws_cfg["key_name"]
            # Create an SSH key to use when logging into instances.
            key = ec2.create_key_pair(aws_cfg["key_name"])

            # Make sure the specified key_dir actually exists.
            # If not, create it.
            key_dir = aws_cfg["key_dir"]
            key_dir = os.path.expanduser(key_dir)
            key_dir = os.path.expandvars(key_dir)
            if not os.path.isdir(key_dir):
                os.mkdir(key_dir, 0700)

            # AWS will store the public key but the private key is
            # generated and returned and needs to be stored locally.
            # The save method will also chmod the file to protect
            # your private key.
            key.save(key_dir)
        else:
            raise

    # Check to see if specified security group already exists.
    # If we get an InvalidGroup.NotFound error back from EC2,
    # it means that it doesn't exist and we need to create it.
    try:
        group = ec2.get_all_security_groups(groupnames=[aws_cfg["group_name"]])[0]
    except ec2.ResponseError, e:
        if e.code == 'InvalidGroup.NotFound':
            print 'Creating Security Group: %s' % aws_cfg["group_name"]
            # Create a security group to control access to instance via SSH.
            group = ec2.create_security_group(aws_cfg["group_name"],
                                              'A group that allows SSH and Web access')
        else:
            raise

    # Add a rule to the security group to authorize SSH traffic
    # on the specified port.
    for port in ["80", "443", aws_cfg["ssh_port"]]:
        try:
            group.authorize('tcp', port, port, "0.0.0.0/0")
        except ec2.ResponseError, e:
            if e.code == 'InvalidPermission.Duplicate':
                print 'Security Group: %s already authorized' % aws_cfg["group_name"]
            else:
                raise

    # rds authorization
    rds = connect_to_rds()
    try:
        rdsGroup = rds.get_all_dbsecurity_groups(groupname=aws_cfg["group_name"])[0]
    except rds.ResponseError, e:
        if e.code == 'DBSecurityGroupNotFound':
            print 'Creating DB Security Group: %s' % aws_cfg["group_name"]
            try:
                # Create a security group to control access to instance via SSH.
                rdsGroup = rds.create_dbsecurity_group(aws_cfg["group_name"],
                                                              'A group that allows Webserver access')
                rdsGroup.authorize(ec2_group=group)
            except Exception, error:
                print _red('Error occured while create security group "%s": %s') %(name, str(error))
                print _yellow('Rolling back!')
                rdsConn.delete_dbsecurity_group(name)
                return
        else:
            raise

@task
def create_rds(name,
                dbName=app_settings["DATABASE_NAME"],
                dbStorageSize=aws_cfg["rds_storage_size"],
                dbInstanceSize=aws_cfg["rds_instance_size"],
                dbUser=app_settings["DATABASE_USER"],
                dbPassword=app_settings["DATABASE_PASS"],
                group_name=aws_cfg["group_name"]):

    conn = connect_to_rds()

    try:
        group = conn.get_all_dbsecurity_groups(groupname=group_name)[0]
    except conn.ResponseError, e:
        setup_aws_account()

    try:
        db = conn.create_dbinstance(id=name, 
                                   allocated_storage=dbStorageSize,
                                   instance_class=dbInstanceSize, 
                                   engine='MySQL', 
                                   master_username=dbUser, 
                                   master_password=dbPassword, 
                                   db_name=dbName, 
                                   security_groups=[group_name])
    except Exception as error:
        print _red('Error occured while provisioning the RDS instance %s' % str(error))
        print name, dbStorageSize, dbInstanceSize, dbUser, dbPassword, dbName, group_name
        return

    print _green('Waiting for rdsInstance to start...')
    status = db.update()
    while status != 'available':
        time.sleep(45)
        status = db.update()
        print _yellow('Still waiting for rdsInstance to start. current status is ') + _red(status)

    if status == 'available':
        print _green('New rdsInstance %s accessible at %s on port %d') % (db.id, db.endpoint[0], db.endpoint[1])
    
    dbHost = str(db.endpoint[0])
    dbPort = str(db.endpoint[1])

    app_settings["DATABASE_HOST"] = dbHost
    app_settings["DATABASE_PORT"] = dbPort
    with open("settings.json", "w") as settingsFile:
        settingsFile.write(json.dumps(app_settings))

    dbConnString = dbHostString + ":" + dbPort
    return dbConnString


@task
def create_instance(name, ami=aws_cfg["ubuntu_lts_ami"],
                    instance_type=aws_cfg["instance_type"],
                    key_name=aws_cfg["key_name"],
                    key_extension='.pem',
                    key_dir='~/.ec2',
                    group_name=aws_cfg["group_name"],
                    ssh_port=22,
                    cidr='0.0.0.0/0',
                    tag=None,
                    user_data=None,
                    cmd_shell=True,
                    login_user='ubuntu',
                    ssh_passwd=None):
    """
    Launch an instance and wait for it to start running.
    Returns a tuple consisting of the Instance object and the CmdShell
    object, if request, or None.

    ami        The ID of the Amazon Machine Image that this instance will
               be based on.  Default is a 64-bit Amazon Linux EBS image.

    instance_type The type of the instance.

    key_name   The name of the SSH Key used for logging into the instance.
               It will be created if it does not exist.

    key_extension The file extension for SSH private key files.

    key_dir    The path to the directory containing SSH private keys.
               This is usually ~/.ssh.

    group_name The name of the security group used to control access
               to the instance.  It will be created if it does not exist.

    ssh_port   The port number you want to use for SSH access (default 22).

    cidr       The CIDR block used to limit access to your instance.

    tag        A name that will be used to tag the instance so we can
               easily find it later.

    user_data  Data that will be passed to the newly started
               instance at launch and will be accessible via
               the metadata service running at http://169.254.169.254.

    cmd_shell  If true, a boto CmdShell object will be created and returned.
               This allows programmatic SSH access to the new instance.

    login_user The user name used when SSH'ing into new instance.  The
               default is 'ec2-user'

    ssh_passwd The password for your SSH key if it is encrypted with a
               passphrase.
    """

    print(_green("Started creating {}...".format(name)))
    print(_yellow("...Creating EC2 instance..."))

    conn = connect_to_ec2()

    try:
        key = conn.get_all_key_pairs(keynames=[key_name])[0]
        group = conn.get_all_security_groups(groupnames=[group_name])[0]
    except conn.ResponseError, e:
        setup_aws_account()

    reservation = conn.run_instances(ami,
        key_name=key_name,
        security_groups=[group_name],
        instance_type=instance_type)

    instance = reservation.instances[0]
    conn.create_tags([instance.id], {"Name":name})
    if tag:
        instance.add_tag(tag)
    while instance.state != u'running':
        print(_yellow("Instance state: %s" % instance.state))
        time.sleep(10)
        instance.update()

    print(_green("Instance state: %s" % instance.state))
    print(_green("Public dns: %s" % instance.public_dns_name))

    if raw_input("Add to ssh/config? (y/n) ").lower() == "y":
        ssh_slug = """
        Host {name}
        HostName {dns}
        Port 22
        User ubuntu
        IdentityFile {key_file_path}
        ForwardAgent yes
        """.format(name=name, dns=instance.public_dns_name, key_file_path=os.path.join(os.path.expanduser(key_dir),
            key_name + key_extension))

        ssh_config = open(os.path.expanduser("~/.ssh/config"), "a")
        ssh_config.write("\n{}\n".format(ssh_slug))
        ssh_config.close()

    if not os.path.isdir("fab_hosts"):
        os.mkdir('fab_hosts')
    f = open("fab_hosts/{}.txt".format(name), "w")
    f.write(instance.public_dns_name)
    f.close()
    return instance.public_dns_name


@task
def terminate_ec2_instance(name):
    """
    Terminates all servers with the given name
    """

    print(_green("Started terminating {}...".format(name)))

    conn = connect_to_ec2()
    filters = {"tag:Name": name}
    for reservation in conn.get_all_instances(filters=filters):
        for instance in reservation.instances:
            if "terminated" in str(instance._state):
                print "instance {} is already terminated".format(instance.id)
                continue
            else:
                print instance._state
            print (instance.id, instance.tags['Name'])
            if raw_input("terminate? (y/n) ").lower() == "y":
                print(_yellow("Terminating {}".format(instance.id)))
                conn.terminate_instances(instance_ids=[instance.id])
                print(_yellow("Terminated"))

@task
def terminate_rds_instance(name):
    """
    Terminates all rds instances with the given name
    """

    print(_green("Started terminating {}...".format(name)))

    conn = connect_to_rds()
    for instance in conn.get_all_dbinstances(instance_id=name):
        if "terminated" in str(instance.status):
            print "instance {} is already terminated".format(instance.id)
            continue
        else:
            print instance.status
        print (instance.id)
        if raw_input("terminate? (y/n) ").lower() == "y":
            print(_yellow("Terminating {}".format(instance.id)))
            conn.delete_dbinstance(id=instance.id, skip_final_snapshot=True)
            print(_yellow("Terminated"))

@task
def bootstrap(name):
    """
    Bootstrap the specified server.

    :param name: The name of the node to be bootstrapped
    :return:
    """

    print(_green("--BOOTSTRAPPING {}--".format(name)))
    f = open("fab_hosts/{}.txt".format(name))
    env.host_string = "ubuntu@{}".format(f.readline().strip())
    package_list = [ 'aptitude', 'ntpdate', 'python-setuptools', 'gcc', 'git-core', 'libxml2-dev', 'libxslt1-dev', 'python-virtualenv', 'python-dev', 'python-lxml', 'libcairo2', 'libpango1.0-0', 'libgdk-pixbuf2.0-0', 'libffi-dev', 'mysql-client', 'libmysqlclient-dev' ]

    update_apt()
    for package in package_list:
        install_package(package)

    sudo('aptitude -y build-dep python-mysqldb')
    install_package('python-mysqldb')

@task
def initapp(name):
    """
    Bootstrap the specified server. Install chef then run chef solo.

    :param name: The name of the node to be bootstrapped
    :param no_install: Optionally skip the Chef installation
    since it takes time and is unneccesary after the first run
    :return:
    """

    print(_green("--DEPLOYING {}--".format(name)))
    f = open("fab_hosts/{}.txt".format(name))
    env.host_string = "ubuntu@{}".format(f.readline().strip())
    sudo("mkdir -p {path} && cd {path} && mkdir -p releases/init shared packages && virtualenv --distribute .".format(path=app_settings["PROJECTPATH"]))

    with cd('{path}'.format(path=app_settings["PROJECTPATH"])):
        sudo("chown -R ubuntu:ubuntu .")
        sudo('pip install django')
        run('cd releases/init && django-admin.py startproject -v3 --template=https://github.com/expa/expa-deploy/archive/master.zip --extension=py,rst,html,conf,xml --name=Vagrantfile --name=crontab {app_name} && cd ../..'.format(app_name=app_settings["APP_NAME"]))
        run('sed -i -e "s:settings\.local:settings\.production:g" releases/init/{app_name}/{app_name}/manage.py'.format(app_name=app_settings["APP_NAME"]))
        run('sed -i -e "s:<DBNAME>:{dbname}:g" -e "s:<DBUSER>:{dbuser}:g" -e "s:<DBPASS>:{dbpass}:g" -e "s:<DBHOST>:{dbhost}:g" -e "s:<DBPORT>:{dbport}:g" releases/init/{app_name}/{app_name}/settings/production.py'.format(dbname=app_settings["DATABASE_NAME"],
                                                                                                                                                                                                                              dbuser=app_settings["DATABASE_USER"],
                                                                                                                                                                                                                              dbpass=app_settings["DATABASE_PASS"],
                                                                                                                                                                                                                              dbhost=app_settings["DATABASE_HOST"],
                                                                                                                                                                                                                              dbport=app_settings["DATABASE_PORT"],
                                                                                                                                                                                                                              app_name=app_settings["APP_NAME"]))
        run("cd ./releases && ln -s init current")
        install_requirements()
        migrate()
        install_web()
        start_webservers()

@task
def restart():
    """
    Reload nginx/gunicorn
    """
    with settings(warn_only=True):
        sudo("supervisorctl restart {app_name}".format(app_name=app_settings["APP_NAME"]))
        sudo('/etc/init.d/nginx reload')

#----------HELPER FUNCTIONS-----------

@contextmanager
def _virtualenv():
    with prefix(env.activate):
        yield

def connect_to_ec2():
    """
    return a connection given credentials imported from config
    """
    return boto.ec2.connect_to_region(aws_cfg["region"],
    aws_access_key_id=aws_cfg["aws_access_key_id"],
    aws_secret_access_key=aws_cfg["aws_secret_access_key"])

def connect_to_rds():
    """
    return a connection given credentials imported from config
    """
    return boto.rds.connect_to_region(aws_cfg["region"],
    aws_access_key_id=aws_cfg["aws_access_key_id"],
    aws_secret_access_key=aws_cfg["aws_secret_access_key"])

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

def install_requirements(release=None):
    "Install the required packages from the requirements file using pip"
    # NOTE ... django requires a global install for some reason
    #require('release', provided_by=[collect])
    if not release:
        release = 'current'

    with cd('{path}'.format(path=app_settings["PROJECTPATH"])):
        # NOTE - there is a weird ass bug with distribute==8 that blows up all setup.py develop installs for eggs from git repos
        run('./bin/pip install --upgrade distribute')
        # run('./bin/pip install --upgrade versiontools')
        
        run('./bin/pip install -r ./releases/{release}/{project_name}/requirements/{requirements_file}.txt'.format(release=release,
                                                                                                                requirements_file=app_settings["REQUIREMENTSFILE"],
                                                                                                                project_name=app_settings["APP_NAME"]))

def migrate():
    "Update the database"
    with cd('{path}/releases/current/{project_name}/{project_name}'.format(path=app_settings["PROJECTPATH"],
                                                            project_name=app_settings["APP_NAME"])):
        run('SECRET_KEY={secretkey} ../../../../bin/python manage.py syncdb --noinput'.format(secretkey=app_settings["DJANGOSECRETKEY"]))
        run('SECRET_KEY={secretkey} ../../../../bin/python manage.py migrate'.format(secretkey=app_settings["DJANGOSECRETKEY"]))
        #run('../../../../bin/python manage.py loaddata app/fixtures/')

def install_web():
    sudo('mkdir -p {path}/tmp/ {path}/pid/ {path}/sock/'.format(path=app_settings["PROJECTPATH"]))

    install_package('nginx')
    if os.path.exists('./config/{project_name}.key'.format(project_name=app_settings["APP_NAME"])) and os.path.exists('./config/{project_name}.crt'):
        put('./config/{{project_name}}.key', '/etc/ssl/private/', use_sudo=True)
        put('./config/{{project_name}}.crt', '/etc/ssl/certs/', use_sudo=True)
        sudo('chown 700 /etc/ssl/private/{{project_name}}.key')
        sudo('chown 644 /etc/ssl/certs/{{project_name}}.crt')

    sudo('pip install uwsgi')
    put('./config/uwsgi /etc/init.d/uwsgi', use_sudo=True)
    put('./config/uwsgi.xml /etc/uwsgi.xml', use_sudo=True)
    put('./config/nginx.conf /etc/nginx/nginx.conf', use_sudo=True)
    sudo('chmod 755 /etc/init.d/uwsgi')

def start_webservers():
    sudo('/etc/init.d/nginx start')
    sudo('/etc/init.d/uwsgi start')

