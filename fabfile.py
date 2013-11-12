import boto
import boto.ec2
import boto.rds
import boto.route53

import os, time, json, string, random, sys

from tempfile import mkdtemp
from contextlib import contextmanager

from fabric.operations import put
from fabric.api import env, local, sudo, run, cd, prefix, task, settings, execute
from fabric.colors import green as _green, yellow as _yellow, red as _red, blue as _blue
from fabric.context_managers import hide, show, lcd
from config import Config

#-----FABRIC TASKS-----------
@task
def setup_aws_account():
    """
    Attempts to setup key pairs and ec2 security groups provided in aws.cfg
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg=loadAwsCfg()

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
def create_rds(name,rdsType='app'):
    """
    Launch an RDS instance with name provided

    returns a string consisting of rds host and port
    """
    try:
        app_settings
    except NameError:
        app_settings=loadSettings(rdsType)

    try:
        aws_cfg
    except NameError:
        aws_cfg=loadAwsCfg()

    dbName=app_settings["DATABASE_NAME"]
    dbStorageSize=aws_cfg["rds_storage_size"]
    dbInstanceSize=aws_cfg["rds_instance_size"]
    dbUser=app_settings["DATABASE_USER"]
    dbPassword=app_settings["DATABASE_PASS"]
    group_name=aws_cfg["group_name"]

    conn = connect_to_rds()

    try:
        group = conn.get_all_dbsecurity_groups(groupname=group_name)[0]
    except conn.ResponseError, e:
        setup_aws_account()

    print(_green("Creating RDS instance {name}...".format(name=name)))

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

    print _yellow('Waiting for rdsInstance to start...')
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
    saveSettings(app_settings, rdsType + '_settings.json')
    
    return str(db.endpoint)

@task
def create_ec2(name,key_extension='.pem',cidr='0.0.0.0/0',tag=None,user_data=None,cmd_shell=True,login_user='ubuntu',ssh_passwd=None,ami=None):

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

    user_data  Data that will be passed to the newly started instance at launch 
               and will be accessible via the metadata service running at http://169.254.169.254.

    cmd_shell  If true, a boto CmdShell object will be created and returned.
               This allows programmatic SSH access to the new instance.

    login_user The user name used when SSH'ing into new instance.  The
               default is 'ec2-user'

    ssh_passwd The password for your SSH key if it is encrypted with a
               passphrase.
    """

    try:
        aws_cfg
    except NameError:
        aws_cfg=loadAwsCfg()

    if ami is None:
        ami=aws_cfg["ubuntu_lts_ami"]
    instance_type=aws_cfg["instance_type"]
    key_name=aws_cfg["key_name"]
    key_dir=aws_cfg["key_dir"]
    group_name=aws_cfg["group_name"]
    ssh_port=aws_cfg["ssh_port"]

    print(_green("Started creating {name} (type/ami: {type}/{ami})...".format(name=name,type=instance_type,ami=ami)))
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

    addToSshConfig(name=name,dns=instance.public_dns_name)

    if not os.path.isdir("fab_hosts"):
        os.mkdir('fab_hosts')
    f = open("fab_hosts/{}.txt".format(name), "w")
    f.write(instance.public_dns_name)
    f.close()
    return instance.public_dns_name

@task
def terminate_ec2(name):
    """
    Terminates all servers with the given name
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg=loadAwsCfg()

    print(_green("Searching for {}...".format(name)))

    conn = connect_to_ec2()
    filters = {"tag:Name": name}
    for reservation in conn.get_all_instances(filters=filters):
        for instance in reservation.instances:
            if "terminated" in str(instance._state):
                print "instance {} is already terminated".format(instance.id)
            else:
                if raw_input("shall we terminate {name}? (y/n) ".format(name=name)).lower() == "y":
                    print(_yellow("Terminating {}".format(instance.id)))
                    conn.terminate_instances(instance_ids=[instance.id])
                    print(_yellow("Terminated"))
                    removeFromSshConfig(instance.public_dns_name)
                    removeDnsEntries(name)

@task
def terminate_rds(name):
    """
    Terminates all rds instances with the given name
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg=loadAwsCfg()

    print(_green("Started terminating {}...".format(name)))

    conn = connect_to_rds()
    for instance in conn.get_all_dbinstances(instance_id=name):
        if "terminated" in str(instance.status):
            print "instance {} is already terminated".format(instance.id)
            continue
        if raw_input("terminate {instance}? (y/n) ".format(instance=instance.id)).lower() == "y":
            print(_yellow("Terminating {}".format(instance.id)))
            conn.delete_dbinstance(id=instance.id, skip_final_snapshot=True)
            print(_yellow("Terminated"))

@task
def getec2instances():
    """
    Returns a list of all ec2 instances
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg=loadAwsCfg()

    # Get a list of instance IDs for the ELB.
    instances = []
    conn = connect_to_elb()
    for elb in conn.get_all_load_balancers():
        instances.extend(elb.instances)
 
    # Get the instance IDs for the reservations.
    conn = connect_to_ec2()
    reservations = conn.get_all_instances([i.id for i in instances])
    instance_ids = []
    for reservation in reservations:
        for i in reservation.instances:
            instance_ids.append(i.id)
 
    # Get the public CNAMES for those instances.
    taggedHosts = []
    for host in conn.get_all_instances(instance_ids):
        taggedHosts.extend([[i.public_dns_name, i.tags['Name'],i.instance_type] for i in host.instances if i.state=='running'])
        taggedHosts.sort() # Put them in a consistent order, so that calling code can do hosts[0] and hosts[1] consistently.
    taggedHosts.sort() # Put them in a consistent order, so that calling code can do hosts[0] and hosts[1] consistently.
    
    if not any(taggedHosts):
        print "no hosts found"
    else:
        if not os.path.isdir("fab_hosts"):
            os.mkdir('fab_hosts')
        for taggedHost in taggedHosts:
            with open("fab_hosts/{}.txt".format(taggedHost[1]), "w") as fabHostFile:
                fabHostFile.write(taggedHost[0])
            print taggedHost[1] + " " + taggedHost[0]

    for taggedHost in taggedHosts:
        addToSshConfig(name=taggedHost[1],dns=taggedHost[0])

@task
def getrdsinstances():
    """
    Returns a list of all rds instances
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg=loadAwsCfg()

    conn = connect_to_rds()
    # Get the public CNAMES for all instances.
    rdsInstances = []
    for rdsInstance in conn.get_all_dbinstances():
        if rdsInstance.status=='available':
            rdsInstances.extend([rdsInstance])
    rdsInstances.sort() # Put them in a consistent order, so that calling code can do hosts[0] and hosts[1] consistently.
 
    if not any(rdsInstances):
        print "no rds instances found"
    else:
        for rdsInstance in rdsInstances:
            print rdsInstance.id
    return rdsInstances

@task
def bootstrap(name,app_type='app'):
    """
    Bootstrap the specified server.

    :param name: The name of the node to be bootstrapped
    :return:
    """
    setHostFromName(name)
    try:
        app_settings
    except NameError:
        app_settings=loadSettings(app_type)
    
    print(_green("--BOOTSTRAPPING {}--".format(name)))
    package_list = ['language-pack-en', 'aptitude', 'git-core', 'mysql-client', 'ntpdate']
    if app_type == 'blog':
        package_list.extend([ 'php5-fpm', 'php5-gd', 'php5-json', 'php5-xcache', 'php5-mysql', 'php5-mcrypt', 'php5-imap', 'php5-geoip', 'php5-sqlite', 'php5-curl', 'php5-cli', 'php5-gd', 'php5-intl', 'php-pear', 'php5-imagick', 'php5-imap', 'php5-mcrypt', 'php5-memcache', 'php5-ming', 'php5-ps', 'php5-pspell', 'php5-recode', 'php5-snmp', 'php5-sqlite', 'php5-tidy', 'php5-xmlrpc', 'php5-xsl', 'nginx'])
    else:
        package_list.extend([ 'python-setuptools', 'gcc', 'git-core', 'libxml2-dev', 'libxslt1-dev', 'python-virtualenv', 'python-dev', 'python-lxml', 'libcairo2', 'libpango1.0-0', 'libgdk-pixbuf2.0-0', 'libffi-dev', 'libmysqlclient-dev' ])

    update_apt()
    install_package('debconf-utils software-properties-common python-software-properties')
    with settings(hide('running', 'stdout')):
        sudo('add-apt-repository -y ppa:apt-fast/stable')
        sudo('echo apt-fast apt-fast/aptmanager select apt-get | debconf-set-selections')
        sudo('echo apt-fast apt-fast/downloadcmd    string  aria2c -c -j ${_MAXNUM} -i ${DLLIST} --connect-timeout=600 --timeout=600 -m0 | debconf-set-selections')
        sudo('echo apt-fast apt-fast/dlflag boolean false | debconf-set-selections')
        sudo('echo apt-fast apt-fast/tmpdownloaddir string  /var/cache/apt/archives/apt-fast| debconf-set-selections')
        sudo('echo apt-fast apt-fast/maxdownloads   string  10| debconf-set-selections')
        sudo('echo apt-fast apt-fast/downloader select  aria2c| debconf-set-selections')
        sudo('echo apt-fast apt-fast/tmpdownloadlist    string  /tmp/apt-fast.list| debconf-set-selections')
        sudo('echo apt-fast apt-fast/aptcache   string  /var/cache/apt/archives| debconf-set-selections')
    update_apt()
    install_package('apt-fast')
    print _blue('Installing packages. please wait...')
    install_package_fast(' '.join(package_list))

    with settings(hide('stdout')):
        sudo('aptitude -y build-dep python-mysqldb')
    install_package_fast('python-mysqldb')
    if app_settings["DATABASE_HOST"] == 'localhost':
        install_mysql_server(name)

@task
def deployapp(name,app_type='app'):
    """
    Deploy app_name module to instance with name alias
    """
    setHostFromName(name)
    try:
        app_settings
    except NameError:
        app_settings=loadSettings(app_type)

    if (app_type == 'expa_core') or (app_type == 'core') or (app_type == 'expacore'):
        release = time.strftime('%Y%m%d%H%M%S')
    else:
        release = collect()

    deploypath = app_settings["PROJECTPATH"] + '/releases/' + release    

    try:
        env.user
        env.group
    except NameError:
        env.user = 'ubuntu'
        env.group = 'ubuntu'

    print(_green("--DEPLOYING {app_type} to {name}--".format(name=name,app_type=app_type)))      
    try:
        env.development
    except NameError:
        if app_settings["DATABASE_HOST"] == 'localhost':
            createlocaldb(name,app_type)

    sudo('[ -d {path} ] || mkdir -p {path}'.format(path=deploypath))
    sudo('chown -R {user}:{group} {path}'.format(path=app_settings["INSTALLROOT"],user=env.user,group=env.group))
    if app_settings["APP_NAME"] in ('expa_core', 'core', 'expacore'):
        with cd('{path}'.format(path=deploypath)):
            run('git clone https://github.com/expa/core.git .')
            run('mkdir config')
            put('./config/*', '{}/config/'.format(deploypath), use_glob=True)
    else:
        upload_tar_from_local(release,app_type)

    with cd('{}'.format(app_settings["PROJECTPATH"])):
        run('virtualenv --distribute .')
        try:
            env.development
        except NameError:
            run('sed -i -e "s:settings\.local:settings\.production:g" releases/{release}/{app_name}/manage.py'.format(app_name=app_settings["APP_NAME"],release=release))
            with settings(hide('running', 'stdout'), warn_only=True):
                run("sed -i -e 's:<DBNAME>:{dbname}:g' -e 's:<DBUSER>:{dbuser}:g' -e 's:<DBPASS>:{dbpass}:g' \
                    -e 's:<DBHOST>:{dbhost}:g' -e 's:<DBPORT>:{dbport}:g' -e 's:<DJANGOSECRETKEY>:{djangosecretkey}:g' \
                    -e 's:<DOMAIN_NAME>:{domain_name}:g' -e 's:<APP_NAME>:{app_name}:g' -e 's:<PROJECTPATH>:{projectpath}:g' -e 's:<HOST_NAME>:{hostname}:g' \
                    releases/{release}/{app_name}/settings/site_settings.py releases/{release}/config/*".format(dbname=app_settings["DATABASE_NAME"],dbuser=app_settings["DATABASE_USER"],
                                                                                                                dbpass=app_settings["DATABASE_PASS"],dbhost=app_settings["DATABASE_HOST"],
                                                                                                                dbport=app_settings["DATABASE_PORT"],djangosecretkey=app_settings["DJANGOSECRETKEY"],
                                                                                                                domain_name=app_settings["DOMAIN_NAME"],release=release,app_name=app_settings["APP_NAME"],
                                                                                                                projectpath=app_settings["PROJECTPATH"],hostname=app_settings["HOST_NAME"]))

    symlink_current_release(release,app_type)
    install_requirements(release,app_type)
    migrate(app_type)
    try:
        env.development
    except NameError:
        install_web(app_type)
        restart(name)
        setup_route53_dns(name, app_type)

@task
def deploywp(name):
    """
    Deploy Wordpress on named ec2 instance. Requires create_rds and bootstrap to be called first with the 'blog' app type
    """
    setHostFromName(name)
    try:
        app_settings
    except NameError:
        app_settings=loadSettings('blog')

    if app_settings["DATABASE_HOST"] == 'localhost':
        createlocaldb(name,'blog')
    
    sudo('mkdir -p {path} {path}/tmp/ {path}/pid/ {path}/sock/; chown ubuntu:ubuntu {path}'.format(path=app_settings["PROJECTPATH"]))
    put('./config/nginx.conf', '/etc/nginx/nginx.conf', use_sudo=True)
    put('./config/blog-nginx.conf', '/etc/nginx/sites-enabled/blog-nginx.conf', use_sudo=True)
    with settings(hide('running', 'stdout')):
        sudo('sed -i -e "s:<PROJECTPATH>:{projectpath}:g" -e "s:<HOST_NAME>:{hostname}:g" /etc/nginx/sites-enabled/blog-nginx.conf'.format(projectpath=app_settings["PROJECTPATH"],hostname=app_settings["HOST_NAME"]))
        run('curl https://raw.github.com/wp-cli/wp-cli.github.com/master/installer.sh | bash')

    with cd('{path}'.format(path=app_settings["PROJECTPATH"])):
        run('export PATH=/home/ubuntu/.wp-cli/bin:$PATH; wp core download')
        with settings(hide('running')):
            run('export PATH=/home/ubuntu/.wp-cli/bin:$PATH; wp core config --dbname={dbname} --dbuser={dbuser} --dbpass={dbpass} --dbhost={dbhost}'.format(dbname=app_settings["DATABASE_NAME"],
                                                                                                                                                        dbuser=app_settings["DATABASE_USER"],
                                                                                                                                                        dbpass=app_settings["DATABASE_PASS"],
                                                                                                                                                        dbhost=app_settings["DATABASE_HOST"]))
            run('export PATH=/home/ubuntu/.wp-cli/bin:$PATH; wp core install --url=http://{host_name} --title="{app_name}" --admin_name={blog_admin} --admin_email={blog_admin_email} --admin_password={blog_pass}'.format(app_name=app_settings["APP_NAME"],
                                                                                                                                                                                                                         host_name=app_settings["HOST_NAME"],
                                                                                                                                                                                                                         blog_admin=app_settings["BLOG_ADMIN"],
                                                                                                                                                                                                                         blog_admin_email=app_settings["BLOG_ADMIN_EMAIL"],
                                                                                                                                                                                                                         blog_pass=app_settings["BLOG_PASS"]))
    sudo('rm -rf /home/ubuntu/.wp-cli')
    sudo('chown -R www-data:www-data {path}'.format(path=app_settings["PROJECTPATH"]))
    restart(name)
    setup_route53_dns(name,'blog')

@task
def localdev():
    try:
        app_settings
    except NameError:
        app_settings=loadSettings('app')

    try:
        core_settings
    except NameError:
        core_settings=loadSettings('core')

    app_settings["REQUIREMENTSFILE"] = 'local'
    core_settings["REQUIREMENTSFILE"] = 'local'
    saveSettings(app_settings,'app_settings.json')
    saveSettings(core_settings,'core_settings.json')
    env.user = 'vagrant'
    env.group = 'vagrant'
    env.target="dev"
    env.development='true'

    bootstrap(env.host_string) 
    sudo('chown -R {user}:{group} {path}'.format(path=app_settings["INSTALLROOT"],user=env.user,group=env.group))
    with cd('{}'.format(app_settings["PROJECTPATH"])):
        run('virtualenv --distribute .')
    install_requirements()
    deployapp(env.host_string, 'core')

@task
def restart(name):
    """
    Reload app server/nginx
    """
    setHostFromName(name)

    with settings(hide('running'), warn_only=True):
        sudo('if [ -x /etc/init.d/php5-fpm ]; then if [ "$( /etc/init.d/php5-fpm status > /dev/null 2>&1 ; echo $? )" = "3" ]; then /etc/init.d/php5-fpm start ; else /etc/init.d/php5-fpm reload ; fi ; fi')
        sudo('if [ -x /etc/init.d/uwsgi ]; then if [ "$( /etc/init.d/uwsgi status > /dev/null 2>&1 ; echo $? )" = "3" ]; then /etc/init.d/uwsgi start ; else /etc/init.d/uwsgi restart ; fi; fi')
        sudo('if [ -x /etc/init.d/nginx ]; then if [ "$( /etc/init.d/nginx status > /dev/null 2>&1 ; echo $? )" = "3" ]; then /etc/init.d/nginx start ; else /etc/init.d/nginx reload ; fi ; fi')

#----------HELPER FUNCTIONS-----------
@contextmanager
def _virtualenv():
    with prefix(env.activate):
        yield

def connect_to_elb():
    """
    return an ec2 connection given credentials imported from config
    """

    try:
        aws_cfg
    except NameError:
        aws_cfg=loadAwsCfg()

    return boto.connect_elb(aws_access_key_id=aws_cfg["aws_access_key_id"],
                            aws_secret_access_key=aws_cfg["aws_secret_access_key"])

def connect_to_ec2():
    """
    return an ec2 connection given credentials imported from config
    """

    try:
        aws_cfg
    except NameError:
        aws_cfg=loadAwsCfg()

    return boto.ec2.connect_to_region(aws_cfg["region"],
                                      aws_access_key_id=aws_cfg["aws_access_key_id"],
                                      aws_secret_access_key=aws_cfg["aws_secret_access_key"])

def connect_to_rds():
    """
    return an rds connection given credentials imported from config
    """

    try:
        aws_cfg
    except NameError:
        aws_cfg=loadAwsCfg()

    return boto.rds.connect_to_region(aws_cfg["region"],
                                      aws_access_key_id=aws_cfg["aws_access_key_id"],
                                      aws_secret_access_key=aws_cfg["aws_secret_access_key"])

def connect_to_r53():
    """
    return a route53 connection given credentials imported from config
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg=loadAwsCfg()
 
    return boto.route53.connect_to_region('universal',
                                          aws_access_key_id=aws_cfg["aws_access_key_id"],
                                          aws_secret_access_key=aws_cfg["aws_secret_access_key"])

def removeDnsEntries(name):
    """
    Remove route53 entries that point to ec2 instance with provided named alias
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg=loadAwsCfg()

    try:
        app_settings
    except NameError:
        app_settings=loadSettings()

    try:
        ec2host = open("fab_hosts/{}.txt".format(name)).readline().strip() + "."
    except IOError:
        print _red("{name} is not reachable. either run fab getec2instances or fab create_ec2:{name} to create the instance".format(name=name))
        return 1
    ec2ip = '.'.join(ec2host.split('.')[0].split('-')[1:5])
    app_zone_name = app_settings["DOMAIN_NAME"] + "."

    print _green("Deleting DNS entries that point to " + name + "/" + ec2host)
    conn = connect_to_r53()

    zone = conn.get_zone(app_zone_name)
    records = zone.get_records()

    for record in records:
        if (record.type == 'CNAME') and (record.to_print() == ec2host):
            print _yellow("...dropping cname " + _green(record.name) + "...")
            zone.delete_cname(record.name)
        elif (record.type == 'A') and (record.to_print() == ec2ip):
            print _yellow("...dropping address record " + _green(record.name) + "...")
            zone.delete_a(record.name)

def setup_route53_dns(name,app_type='app'):
    """
    Creates Route53 DNS entries for given ec2 instance and app_type
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg=loadAwsCfg()

    try:
        app_settings
    except NameError:
        app_settings = loadSettings(app_type)

    try:
        ec2host = open("fab_hosts/{}.txt".format(name)).readline().strip() + "."
    except IOError:
        print _red("{name} is not reachable. either run fab getec2instances or fab create_ec2:{name} to create the instance".format(name=name))
        return 1

    app_zone_name = app_settings["DOMAIN_NAME"] + "."
    app_host_name = app_settings["HOST_NAME"] + "."

    print _green("Creating DNS for " + name + " and app_type " + app_type)
    conn = connect_to_r53()
    if conn.get_zone(app_zone_name) is None:
        print _yellow("creating zone " + _green(app_zone_name))
        zone = conn.create_zone(app_zone_name)
    else:
        print _yellow("zone " + _green(app_zone_name) + _yellow(" already exists. skipping creation"))
        zone = conn.get_zone(app_zone_name)
    
    if app_type == 'app':
        # TODO: cleanup parser
        # ex: ec2-54-204-216-244.compute-1.amazonaws.com
        ec2ip = '.'.join(ec2host.split('.')[0].split('-')[1:5])
        try:
            apex = zone.add_a(app_zone_name,ec2ip,ttl=300)
            while apex.status != 'INSYNC':
                print _yellow("creation of A record: " + _green(app_zone_name + " " + ec2ip) + _yellow(" is ") + _red(apex.status))
                apex.update()
                time.sleep(10)
            else:
                print _green("creation of A record: " + app_zone_name + " is now " + apex.status)
        except Exception as e:
            if 'already exists' in e.message:
                print _yellow("address record " + _green(app_zone_name + " " + ec2ip) + _yellow(" already exists. skipping creation"))
            else:
                raise

    try:
        cname = zone.add_cname(app_host_name,ec2host,ttl=300,comment="expa " + app_type + " entry")
        while cname.status != 'INSYNC':
            print _yellow("creation of cname: " + _green(app_host_name) + _yellow(" is ") + _red(cname.status))            
            cname.update()            
            time.sleep(10)
        else:
            print _green("creation of cname: " + app_host_name + " is now " + cname.status)            
    except Exception as e:
        if 'already exists' in e.message:
            print _yellow("cname record " + _green(app_host_name) + _yellow(" already exists. skipping creation"))
        else:
            raise
        
def loadAwsCfg():
    try:
        aws_cfg = Config(open("aws.cfg"))
        env.key_filename = os.path.expanduser(os.path.join(aws_cfg["key_dir"],  
                                                           aws_cfg["key_name"] + ".pem"))
        return aws_cfg
    except Exception as e:
        print "aws.cfg not found. %s" %e
        return 1

def install_requirements(release=None,app_type='app'):
    "Install the required packages from the requirements file using pip"
    # NOTE ... django requires a global install for some reason
    try:
        app_settings
    except NameError:
        app_settings=loadSettings(app_type)

    if release is None:
        release = 'current'

    with cd('{path}'.format(path=app_settings["PROJECTPATH"])):
        # NOTE - there is a weird ass bug with distribute==8 that blows up all setup.py develop installs for eggs from git repos
        run('./bin/pip install --upgrade distribute')
        # run('./bin/pip install --upgrade versiontools')
        
        run('./bin/pip install -r ./releases/{release}/requirements/{requirements_file}.txt'.format(release=release,
                                                                                                    requirements_file=app_settings["REQUIREMENTSFILE"]))

def migrate(app_type):
    "Update the database"
    try:
        app_settings
    except NameError:
        app_settings=loadSettings(app_type)

    with cd('{path}/releases/current/{app_name}'.format(path=app_settings["PROJECTPATH"],app_name=app_settings["APP_NAME"])):
        with settings(hide('running')):
            print _yellow('Running syncdb...')
            run("SECRET_KEY='{secretkey}' ../../../bin/python manage.py syncdb --noinput".format(secretkey=app_settings["DJANGOSECRETKEY"]))
            print _yellow('Running migrate...')
            run("SECRET_KEY='{secretkey}' ../../../bin/python manage.py migrate".format(secretkey=app_settings["DJANGOSECRETKEY"]))
            #run('../../../bin/python manage.py loaddata app/fixtures/')

def install_web(app_type='app'):
    "Install web serving components"

    try:
        app_settings
    except NameError:
        app_settings=loadSettings(app_type)

    sudo('mkdir -p {path}/tmp/ {path}/pid/ {path}/sock/'.format(path=app_settings["PROJECTPATH"]), warn_only=True)

    install_package('nginx')
    if os.path.exists('./keys/{{project_name}}.key') and os.path.exists('./keys/{{project_name}}.crt'):
        put('./keys/{{project_name}}.key', '/etc/ssl/private/', use_sudo=True)
        put('./keys/{{project_name}}.crt', '/etc/ssl/certs/', use_sudo=True)
        sudo('chown 700 /etc/ssl/private/{{project_name}}.key')
        sudo('chown 644 /etc/ssl/certs/{{project_name}}.crt')

    sudo('pip install uwsgi')
    with cd('{path}/releases/current'.format(path=app_settings["PROJECTPATH"])):
        sudo('cp ./config/uwsgi /etc/init.d/uwsgi')
        sudo('if [ ! -d /etc/uwsgi ]; then mkdir /etc/uwsgi ; fi')
        sudo('cp ./config/{app_type}-uwsgi.xml /etc/uwsgi/'.format(app_type=app_type))
        sudo('cp ./config/nginx.conf /etc/nginx/')
        sudo('cp ./config/{app_type}-nginx.conf /etc/nginx/sites-enabled/{app_name}-nginx.conf'.format(app_type=app_type,app_name=app_settings["APP_NAME"]))
    sudo('chmod 755 /etc/init.d/uwsgi')

def install_mysql_server(name):
    """
    Install mysql server on named instance
    """
    setHostFromName(name)
    
    try:
        app_settings
    except NameError:
        app_settings=loadSettings()

    try:
        app_settings["LOCAL_MYSQL_PASS"]
    except KeyError:
        app_settings["LOCAL_MYSQL_PASS"] = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for ii in range(32))
        saveSettings(app_settings, 'app_settings.json')
        
    update_apt()
    install_package('debconf-utils')
    with settings(hide('running', 'stdout')):
        sudo('echo mysql-server-5.5 mysql-server/root_password password {dbpass} | debconf-set-selections'.format(dbpass=app_settings["LOCAL_MYSQL_PASS"]))
        sudo('echo mysql-server-5.5 mysql-server/root_password_again password {dbpass} | debconf-set-selections'.format(dbpass=app_settings["LOCAL_MYSQL_PASS"]))

    install_package('mysql-server-5.5')

def start_webservers():
    sudo('/etc/init.d/nginx start')
    sudo('/etc/init.d/uwsgi start')

def collect():
    """
    Create deployable tarball.

    return: release number as a string
    """
    release = time.strftime('%Y%m%d%H%M%S')
    local("find . -name '*.pyc' -delete", capture=False)

    #local('python ./{{project_name}}/manage.py collectstatic --settings={{project_name}}.settings.init_deploy  --noinput ')
    #local('python ./{{project_name}}/manage.py compress --settings={{project_name}}.settings.init_deploy ')
    local('python ./{{project_name}}/manage.py collectstatic --noinput ')
    local('tar -cjf  {release}.tbz --exclude=keys/* --exclude=aws.cfg --exclude=settings.json --exclude=fab_hosts/* --exclude=.git --exclude={{project_name}}/media *'.format(release=release))
    return release

def symlink_current_release(release,app_type):
    "Symlink our current release"
    try:
        app_settings
    except NameError:
        app_settings=loadSettings(app_type)

    with cd('{path}'.format(path=app_settings["PROJECTPATH"])):
        run('rm releases/previous; mv releases/current releases/previous; ln -s {release} releases/current'.format(release=release))

def upload_tar_from_local(release=None,app_type='app'):
    "Create an archive from the current Git master branch and upload it"
    try:
        app_settings
    except NameError:
        app_settings=loadSettings(app_type)

    if release is None:
        release = collect()
    
    run('mkdir -p {path}/releases/{release} {path}/packages'.format(path=app_settings["PROJECTPATH"],release=release))
    put('{release}.tbz'.format(release=release), '{path}/packages/'.format(path=app_settings["PROJECTPATH"],release=release))
    run('cd {path}/releases/{release} && tar xjf ../../packages/{release}.tbz'.format(path=app_settings["PROJECTPATH"],release=release))
    sudo('rm {path}/packages/{release}.tbz'.format(path=app_settings["PROJECTPATH"],release=release))
    local('rm {release}.tbz'.format(release=release))

def createlocaldb(name,app_type='app'):
    """
    Create a local mysql db on named instance with given app settings.
    """
    try:
        app_settings
    except NameError:
        app_settings=loadSettings()

    try:
        local_app_settings
    except NameError:
        local_app_settings=loadSettings(app_type)

    try:
        with settings(hide('running','warnings')):
            sudo('mysqladmin -p{mysql_root_pass} create {dbname}'.format(mysql_root_pass=app_settings["LOCAL_MYSQL_PASS"],dbname=local_app_settings["DATABASE_NAME"]), warn_only=True)
            sudo('mysql -uroot -p{mysql_root_pass} -e "GRANT ALL PRIVILEGES ON {dbname}.* to {dbuser}@\'localhost\' IDENTIFIED BY \'{dbpass}\'"'.format(mysql_root_pass=app_settings["LOCAL_MYSQL_PASS"],
                                                                                                                                                    dbname=local_app_settings["DATABASE_NAME"],
                                                                                                                                                    dbuser=local_app_settings["DATABASE_USER"],
                                                                                                                                                    dbpass=local_app_settings["DATABASE_PASS"]))
    except Exception as e:
        print e
        pass

def install_package(name):
    """ install a package using APT """
    with settings(hide('running', 'stdout'), warn_only=True):
        print _yellow('Installing package %s... ' % name),
        sudo('apt-get -qq -y --force-yes install %s' % name)
        print _green('[DONE]')

def install_package_fast(name):
    """ install a package using APT """
    with settings(hide('running', 'stdout'), warn_only=True):
        print _yellow('Installing package %s... ' % name),
        sudo('apt-fast -qq -y --force-yes install %s' % name)
        print _green('[DONE]')

def update_apt():
    """ run apt-get update """
    with settings(hide('running', 'stdout'), warn_only=True):
        print _yellow('Updating APT cache... '),
        sudo('apt-get update')
        print _green('[DONE]')

def saveSettings(appSettingsJson,settingsFile):
    #print _red("saving settings to: " + settingsFile)
    with open(settingsFile, "w") as settingsFile:
        settingsFile.write(json.dumps(appSettingsJson,indent=4,separators=(',', ': '),sort_keys=True))

def loadSettings(app_type='app'):
    settingsFile = app_type + '_settings.json'
    
    try:
        with open(settingsFile, "r") as settingsFile:
            settings = json.load(settingsFile)
    except Exception as e:
        settings = generateDefaultSettings(app_type)
        saveSettings(settings,settingsFile)
    return settings

def generateDefaultSettings(settingsType):
    if (settingsType == 'expa_core') or (settingsType == 'core') or (settingsType == 'expacore') :
        app_settings = {"DATABASE_USER": "expacore",
                        # RDS password limit is 41 characters and only printable chars. Felt weird so we'll make it 32.
                        "DATABASE_PASS": ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for ii in range(32)),
                        "APP_NAME": "expa_core",
                        "DATABASE_NAME": "expacore",
                        "DATABASE_HOST": "localhost",
                        "DATABASE_PORT": "3306",
                        "PROJECTPATH" : "/mnt/ym/expacore",
                        "REQUIREMENTSFILE" : "production",
                        "DOMAIN_NAME" : "demo.expa.com",
                        "HOST_NAME" : "core.demo.expa.com",
                        "INSTALLROOT" : "/mnt/ym",
                        "DJANGOSECRETKEY" : ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits + '@#$%^&*()') for ii in range(64))
                        }

    elif settingsType == 'blog':
        app_settings = {"DATABASE_USER": "{{project_name}}_blog",
                        # RDS password limit is 41 characters and only printable chars. Felt weird so we'll make it 32.
                        "DATABASE_PASS": ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for ii in range(32)),
                        "APP_NAME": "blog",
                        "DATABASE_NAME": "blog",
                        "DATABASE_HOST": "localhost",
                        "DATABASE_PORT": "3306",
                        "PROJECTPATH" : "/mnt/ym/blog",
                        "REQUIREMENTSFILE" : "production",
                        "DOMAIN_NAME" : "demo.expa.com",
                        "HOST_NAME" : "blog.demo.expa.com",
                        "INSTALLROOT" : "/mnt/ym",
                        "BLOG_ADMIN" : "{{project_name}}_admin",
                        "BLOG_ADMIN_EMAIL" : "{{project_name}}_admin@{{project_name}}.com",
                        "BLOG_PASS" : ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for ii in range(16))
                        }
    else:
        app_settings = {"DATABASE_USER": "{{project_name}}",
                        # RDS password limit is 41 characters and only printable chars. Felt weird so we'll make it 32.
                        "DATABASE_PASS": ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for ii in range(32)),
                        "APP_NAME": "{{project_name}}",
                        "DATABASE_NAME": "{{project_name}}",
                        "DATABASE_HOST": "localhost",
                        "DATABASE_PORT": "3306",
                        "PROJECTPATH" : "/mnt/ym/{{project_name}}",
                        "REQUIREMENTSFILE" : "production",
                        "DOMAIN_NAME" : "demo.expa.com",
                        "HOST_NAME" : "www.demo.expa.com",
                        "INSTALLROOT" : "/mnt/ym",
                        "DJANGOSECRETKEY" : ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits + '@#$%^&*()') for ii in range(64))
                        }
    return app_settings

def addToSshConfig(name,dns):
    """
    Add provided hostname and dns to ssh_config with config template below
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg=loadAwsCfg()

    ssh_slug = """
    Host {name}
    HostName {dns}
    Port 22
    User ubuntu
    IdentityFile {key_file_path}
    ForwardAgent yes
    """.format(name=name, dns=dns, key_file_path=os.path.join(os.path.expanduser(aws_cfg["key_dir"]),aws_cfg["key_name"] + ".pem"))
    if os.name == 'posix':
        try:
            with open(os.path.expanduser("~/.ssh/config"), "a+") as ssh_config:
                ssh_config.seek(0)
                if not dns in ssh_config.read():
                    ssh_config.seek(0,2)
                    ssh_config.write("\n{}\n".format(ssh_slug))
        except Exception as e:
            print e
            pass

def removeFromSshConfig(dns):
    """
    Remove ssh_slug containing provided name and dns from ssh_config
    """
    if os.name == 'posix':
        try:
            with open(os.path.expanduser("~/.ssh/config"), "r+") as ssh_config:
                lines = ssh_config.readlines()
                blockstart = substringIndex(lines, dns)
                blockend = substringIndex(lines, "ForwardAgent yes", blockstart)
                del(lines[blockstart-2:blockend+2])
                ssh_config.seek(0)
                ssh_config.write(''.join(lines))
                ssh_config.truncate()
        except Exception as e:
            print e

def setHostFromName(name):
    if env.host_string is None:
        f = open("fab_hosts/{}.txt".format(name))
        env.host_string = "ubuntu@{}".format(f.readline().strip())

def substringIndex(the_list, substring, offset=0):
    for i, s in enumerate(the_list):
        if (substring in s) and ( i >= offset):
            return i
    return -1
