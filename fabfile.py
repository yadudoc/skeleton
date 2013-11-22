import boto.ec2, boto.rds, boto.route53, boto.s3, boto.iam
import aws, os, time, json, string, random, subprocess

from contextlib import contextmanager

from fabric.operations import put
from fabric.api import env, local, sudo, run, cd, prefix
from fabric.api import task, settings
from fabric.colors import green as _green, yellow as _yellow
from fabric.colors import red as _red, blue as _blue
from fabric.context_managers import hide

#-----FABRIC TASKS-----------
@task
def create_rds(name, app_type, engine_type):
    """
    Launch an RDS instance with name provided

    returns a string consisting of rds host and port
    """
    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)

    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    conn = connect_to_rds()

    try:
        group = conn.get_all_dbsecurity_groups(groupname=aws_cfg.get("aws", "group_name"))[0]
    except conn.ResponseError, error:
        setup_aws_account()
        group = conn.get_all_dbsecurity_groups(groupname=aws_cfg.get("aws", "group_name"))[0]

    print(_green("Creating RDS instance {name}...".format(name=name)))

    try:
        dbinstance = conn.create_dbinstance(id=name,
                                   allocated_storage=aws_cfg.get("rds", "rds_storage_size"),
                                   instance_class=aws_cfg.get("rds", "rds_instance_size"),
                                   engine=engine_type,
                                   master_username=app_settings["DATABASE_USER"],
                                   master_password=app_settings["DATABASE_PASS"],
                                   db_name=app_settings["DATABASE_NAME"],
                                   security_groups=[group])
    except Exception as error:
        print _red('Error occured while provisioning the RDS instance  %s' % str(error))
        print name, aws_cfg.get("rds","rds_storage_size"), aws_cfg.get("rds", "rds_instance_size"), app_settings["DATABASE_USER"], app_settings["DATABASE_PASS"], app_settings["DATABASE_NAME"], group
        return

    print _yellow('Waiting for rdsInstance to start...')
    status = dbinstance.update()
    while status != 'available':
        time.sleep(45)
        status = dbinstance.update()
        print _yellow('Still waiting for rdsInstance to start. current status is ') + _red(status)

    if status == 'available':
        print _green('New rdsInstance %s accessible at %s on port %d') % (dbinstance.id, dbinstance.endpoint[0], dbinstance.endpoint[1])

    dbhost = str(dbinstance.endpoint[0])
    dbport = str(dbinstance.endpoint[1])

    app_settings["DATABASE_HOST"] = dbhost
    app_settings["DATABASE_PORT"] = dbport
    savesettings(app_settings, app_type + '_settings.json')

    return str(dbinstance.endpoint)

@task
def create_ec2(name, tag=None, ami=None):

    """
    Launch an instance and wait until we can connect to it.
    Returns the public dns name of the instance we created.

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
        aws_cfg = load_aws_cfg()

    if ami is None:
        ami = aws_cfg.get("micro", "ubuntu_lts_ami")
    instance_type = aws_cfg.get("micro", "instance_type")
    key_name = aws_cfg.get("aws", "key_name")
    group_name = aws_cfg.get("aws", "group_name")

    print(_green("Started creating {name} (type/ami: {type}/{ami})...".format(name=name, type=instance_type, ami=ami)))
    print(_yellow("...Creating EC2 instance..."))

    conn = connect_to_ec2()

    try:
        key = conn.get_all_key_pairs(keynames=[key_name])[0]
        group = conn.get_all_security_groups(groupnames=[group_name])[0]
    except conn.ResponseError:
        setup_aws_account()
        key = conn.get_all_key_pairs(keynames=[key_name])[0]
        group = conn.get_all_security_groups(groupnames=[group_name])[0]

    reservation = conn.run_instances(ami,
        key_name=key.name,
        security_groups=[group],
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

    addtosshconfig(name=name, dns=instance.public_dns_name)

    if not os.path.isdir("fab_hosts"):
        os.mkdir('fab_hosts')
    hostfile = open("fab_hosts/{}.txt".format(name), "w")
    hostfile.write(instance.public_dns_name)
    hostfile.close()

    print _yellow("testing connectivity to instance: ") + _green(name)
    connectivity = False
    while connectivity is False:
        try:
            sethostfromname(name)
            with settings(hide('running','stdout')):
                run('uname')
            connectivity = True
        except Exception:
            time.sleep(5)
    return instance.public_dns_name

@task
def create_vpc():
    """
    Make VPC with name
    """
    bastion_hosts = aws.make_vpc()
    for host in bastion_hosts:
        if not os.path.isdir("fab_hosts"):
            os.mkdir('fab_hosts')
        hostfile = open("fab_hosts/{}.txt".format(host.name), "w")
        hostfile.write(host.public_ip)
        hostfile.close()
        addtosshconfig(host.name, host.public_ip)

@task
def delete_vpc():
    """
    Delete VPC - by default the vpc_name is 'midkemia'
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()
    bastion_hosts = []

    aws.delete_vpc()
    for section in aws_cfg.sections():
        try:
            bastion_hosts.append(aws_cfg.get(section, "bastion_host"))
        except Exception:
            pass

    for bastion_host in bastion_hosts:
        path = './fab_hosts/' + bastion_host + '.txt'
        public_ip = open(path).readline().strip()
        if os.path.isfile(path):
            os.remove(path)
        removefromsshconfig(public_ip)

@task
def terminate_ec2(name):
    """
    Terminates all servers with the given name
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    print(_green("Searching for {}...".format(name)))

    conn = connect_to_ec2()
    filters = {"tag:Name": name}
    for reservation in conn.get_all_instances(filters=filters):
        for instance in reservation.instances:
            if "terminated" in str(instance.state):
                print "instance {} is already terminated".format(instance.id)
            else:
                if raw_input("shall we terminate {name}/{id}/{dns}? (y/n) ".format(name=name, id=instance.id, dns=instance.public_dns_name)).lower() == "y":
                    print(_yellow("Terminating {}".format(instance.id)))
                    conn.terminate_instances(instance_ids=[instance.id])
                    print(_yellow("Terminated"))
                    removefromsshconfig(instance.public_dns_name)
                    remove_dns_entries(name, 'app')

@task
def terminate_rds(name):
    """
    Terminates all rds instances with the given name
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

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
        aws_cfg = load_aws_cfg()

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
    taggedhosts = []
    for host in conn.get_all_instances(instance_ids):
        taggedhosts.extend([[i.public_dns_name, i.tags['Name'], i.instance_type] for i in host.instances if i.state=='running'])
        taggedhosts.sort() # Put them in a consistent order, so that calling code can do hosts[0] and hosts[1] consistently.
    taggedhosts.sort() # Put them in a consistent order, so that calling code can do hosts[0] and hosts[1] consistently.

    if not any(taggedhosts):
        print "no hosts found"
    else:
        if not os.path.isdir("fab_hosts"):
            os.mkdir('fab_hosts')
        for taggedhost in taggedhosts:
            with open("fab_hosts/{}.txt".format(taggedhost[1]), "w") as fabhostfile:
                fabhostfile.write(taggedhost[0])
            print taggedhost[1] + " " + taggedhost[0]

    for taggedhost in taggedhosts:
        addtosshconfig(name=taggedhost[1], dns=taggedhost[0])

@task
def getrdsinstances():
    """
    Returns a list of all rds instances
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    conn = connect_to_rds()
    # Get the public CNAMES for all instances.
    rdsinstances = []
    for rdsinstance in conn.get_all_dbinstances():
        if rdsinstance.status == 'available':
            rdsinstances.extend([rdsinstance])
    rdsinstances.sort() # Put them in a consistent order, so that calling code can do hosts[0] and hosts[1] consistently.

    if not any(rdsinstances):
        print "no rds instances found"
    else:
        for rdsinstance in rdsinstances:
            print rdsinstance.id
    return rdsinstances

@task
def bootstrap(name, app_type):
    """
    Bootstrap the specified server.

    :param name: The name of the node to be bootstrapped
    :return:
    """
    sethostfromname(name)
    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)

    print(_green("--BOOTSTRAPPING {name} for {app_type}--".format(name=name, app_type=app_type)))
    package_list = ['language-pack-en', 'aptitude', 'git-core', 'ntpdate']
    if app_type == 'blog':
        package_list.extend([ 'php5-fpm', 'php5-gd', 'php5-json', 'php5-xcache', 'php5-mysql', 'php5-mcrypt', 'php5-imap', 'php5-geoip', 'php5-sqlite', 'php5-curl', 'php5-cli', 'php5-gd', 'php5-intl', 'php-pear', 'php5-imagick', 'php5-imap', 'php5-mcrypt', 'php5-memcache', 'php5-ming', 'php5-ps', 'php5-pspell', 'php5-recode', 'php5-snmp', 'php5-sqlite', 'php5-tidy', 'php5-xmlrpc', 'php5-xsl', 'nginx'])
    else:
        package_list.extend([ 'python-setuptools', 'gcc', 'git-core', 'libxml2-dev', 'libxslt1-dev', 'python-virtualenv', 'python-dev', 'python-lxml', 'libcairo2', 'libpango1.0-0', 'libgdk-pixbuf2.0-0', 'libffi-dev', 'libmysqlclient-dev' ])

    with settings(hide('stdout')):
        if app_settings["DB_TYPE"] == 'mysql':
            package_list.extend([ 'mysql-client' ])        
            sudo('aptitude -y build-dep python-mysqldb')
        elif app_settings["DB_TYPE"] == 'postgresql':
            package_list.extend([ 'postgresql-client-common' , 'postgresql-client-9.3' ])
            sudo('aptitude -y build-dep python-psycopg2')
    if app_settings["APP_NAME"] == 'expa_gis':
        package_list.extend([ 'postgis' ])

    update_apt()
    install_package('debconf-utils software-properties-common python-software-properties')
    with settings(hide('running', 'stdout')):
        sudo('echo "deb http://us.archive.ubuntu.com/ubuntu/ precise main universe multiverse"  > /etc/apt/sources.list.d/ubuntu-multiverse.list')
        sudo('echo "deb http://apt.postgresql.org/pub/repos/apt/ precise-pgdg main"  > /etc/apt/sources.list.d/postgresql.list')
        sudo('wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -')
    update_apt()
    print _blue('Installing packages. please wait...')
    install_package(' '.join(package_list))
    with settings(hide('stdout')):
        sudo('apt-get -qq -y --force-yes remove s3cmd')
        sudo('apt-get -qq -y upgrade')
    sudo('pip install -q --upgrade s3cmd')

    if app_settings["DATABASE_HOST"] == 'localhost':
        install_localdb_server(name, app_settings["DB_TYPE"])

@task
def deployapp(name, app_type):
    """
    Deploy app_name module to instance with name alias
    """
    sethostfromname(name)
    try:
        git_cfg
    except NameError:
        git_cfg = load_git_cfg()

    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)

    if app_type in ('expa_core', 'core', 'expacore', 'expa_gis', 'gis'):
        release = time.strftime('%Y%m%d%H%M%S')
    else:
        release = collectlocal()

    deploypath = app_settings["PROJECTPATH"] + '/releases/' + release

    if env.host_string != '127.0.0.1':
        env.user = 'ubuntu'
        env.group = 'ubuntu'

    print(_green("--DEPLOYING {app_type} to {name}--".format(name=name, app_type=app_type)))
    try:
        env.development
    except AttributeError:
        if app_settings["DATABASE_HOST"] == 'localhost':
            createlocaldb(app_type, app_settings["DB_TYPE"])
        else:
            if app_settings["APP_NAME"] == 'expa_gis':
                with settings(hide('running')):
                    run('export PGPASSWORD={dbpass}; psql -h {dbhost} -p {dbport} -U {dbuser} -w -c "CREATE EXTENSION postgis; CREATE EXTENSION postgis_topology;" -d {dbname}'.format(dbhost=app_settings["DATABASE_HOST"],
                                                                                                                                                                                       dbport=app_settings["DATABASE_PORT"],
                                                                                                                                                                                       dbuser=app_settings["DATABASE_USER"], 
                                                                                                                                                                                       dbname=app_settings["DATABASE_NAME"],
                                                                                                                                                                                       dbpass=app_settings["DATABASE_PASS"]),
                                                                                                                                                                                       warn_only=True)

    sudo('[ -d {path} ] || mkdir -p {path}'.format(path=deploypath))
    sudo('chown -R {user}:{group} {path}'.format(path=app_settings["INSTALLROOT"], user=env.user, group=env.group))
    if app_settings["APP_NAME"] in ('expa_core', 'expa_gis'):
        with cd('{path}'.format(path=deploypath)):
            run('echo "StrictHostKeyChecking no" >> ~/.ssh/config', quiet=True)
            put('{key_dir}/{key}'.format(key_dir=git_cfg.get("git", "key_dir"), key=git_cfg.get("git", app_type+"_deploy_key")), '~/.ssh/id_rsa', mode=0600)
            run('git clone -q git@github.com:/{github_user}/{github_repo}.git .'.format(github_user=git_cfg.get("git", "user_name"), github_repo=app_type))
            run('rm ~/.ssh/id_rsa')
            run('mkdir config')
            put('./config/*', '{}/config/'.format(deploypath), use_glob=True)
    else:
        upload_tar_from_local(release, app_type)

    with cd('{}'.format(app_settings["PROJECTPATH"])):
        run('virtualenv --distribute .')
        try:
            env.development
        except AttributeError:
            with settings(hide('running', 'stdout'), warn_only=True):
                run("sed -i -e 's:<APP_NAME>:{app_name}:g' -e 's:<PROJECTPATH>:{projectpath}:g' \
                    releases/{release}/config/*".format(release=release, app_name=app_settings["APP_NAME"], 
                                                        projectpath=app_settings["PROJECTPATH"], hostname=app_settings["HOST_NAME"]))
    symlink_current_release(release, app_type)
    install_requirements(release, app_type)
    if app_settings["APP_NAME"] in ('expa_core', 'core', 'expacore', 'expa_gis'):
        with cd('{}'.format(app_settings["PROJECTPATH"])):
            collectremote(name, app_type, release)
            migrate(app_type)
            with settings(hide('running')):
                run('echo "from django.contrib.auth.models import User; User.objects.create_superuser(\'{admin}\', \'{adminemail}\', \'{adminpass}\')" \
                    | ./bin/python ./releases/{release}/{app_name}/manage.py shell'.format(admin=app_settings["ADMIN_USER"],
                                                                                          adminemail=app_settings["ADMIN_EMAIL"],
                                                                                          adminpass=app_settings["ADMIN_PASS"],
                                                                                          release=release, app_name=app_settings["APP_NAME"]))
                
    else:
        migrate(app_type)
    try:
        env.development
    except AttributeError:
        install_web(app_type)
        restart(name)
        setup_route53_dns(name, app_type)

@task
def deploywp(name):
    """
    Deploy Wordpress on named ec2 instance. Requires create_rds and bootstrap to be called first with the 'blog' app type
    """
    sethostfromname(name)
    try:
        app_settings
    except NameError:
        app_settings = loadsettings('blog')

    print(_green("--DEPLOYING wordpress to {name}--".format(name=name)))
    if app_settings["DATABASE_HOST"] == 'localhost':
        createlocaldb('blog')

    sudo('mkdir -p {path} {path}/tmp/ {path}/pid/ {path}/sock/; chown ubuntu:ubuntu {path}'.format(path=app_settings["PROJECTPATH"]))
    put('./config/nginx.conf', '/etc/nginx/nginx.conf', use_sudo=True)
    put('./config/blog-nginx.conf', '/etc/nginx/sites-enabled/blog-nginx.conf', use_sudo=True)
    with settings(hide('running', 'stdout')):
        sudo('sed -i -e "s:<PROJECTPATH>:{projectpath}:g" -e "s:<HOST_NAME>:{hostname}:g" /etc/nginx/sites-enabled/blog-nginx.conf'.format(projectpath=app_settings["PROJECTPATH"], hostname=app_settings["HOST_NAME"]))
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
    """
    Deploy core and skeleton app to local vagrant. For use with vagrant up and provided VagrantFile
    """
    try:
        app_settings
    except NameError:
        app_settings = loadsettings('app')

    try:
        core_settings
    except NameError:
        core_settings = loadsettings('core')

    try:
        gis_settings
    except NameError:
        gis_settings = loadsettings('gis')

    app_settings["REQUIREMENTSFILE"] = 'local'
    core_settings["REQUIREMENTSFILE"] = 'local'
    gis_settings["REQUIREMENTSFILE"] = 'local'
    savesettings(app_settings,'app_settings.json')
    savesettings(core_settings,'core_settings.json')
    savesettings(gis_settings,'gis_settings.json')
    env.user = 'vagrant'
    env.group = 'vagrant'
    env.target = 'dev'
    env.development = 'true'

    bootstrap(env.host_string,'app')
    sudo('chown -R {user}:{group} {path}'.format(path=app_settings["INSTALLROOT"], user=env.user, group=env.group))
    with cd('{}'.format(app_settings["PROJECTPATH"])):
        run('virtualenv --distribute .')
    install_requirements()
    deployapp(env.host_string, 'core')
    deployapp(env.host_string, 'gis')

@task
def restart(name):
    """
    Reload app server/nginx
    """
    sethostfromname(name)

    with settings(hide('running'), warn_only=True):
        sudo('if [ -x /etc/init.d/php5-fpm ]; then if [ "$( /etc/init.d/php5-fpm status > /dev/null 2>&1 ; echo $? )" = "3" ]; then /etc/init.d/php5-fpm start ; else /etc/init.d/php5-fpm reload ; fi ; fi')
        sudo('if [ -x /etc/init.d/uwsgi ]; then if [ "$( /etc/init.d/uwsgi status > /dev/null 2>&1 ; echo $? )" = "3" ]; then /etc/init.d/uwsgi start ; else /etc/init.d/uwsgi restart ; fi; fi')
        sudo('if [ -x /etc/init.d/nginx ]; then if [ "$( /etc/init.d/nginx status > /dev/null 2>&1 ; echo $? )" = "3" ]; then /etc/init.d/nginx start ; else /etc/init.d/nginx reload ; fi ; fi')

#----------HELPER FUNCTIONS-----------
@contextmanager
def _virtualenv():
    """
    Activate virtual environment
    """
    with prefix(env.activate):
        yield

def connect_to_elb():
    """
    return an ec2 connection given credentials imported from config
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    return boto.connect_elb(aws_access_key_id=aws_cfg.get("aws", "access_key_id"),
                            aws_secret_access_key=aws_cfg.get("aws", "secret_access_key"))

def connect_to_ec2():
    """
    return an ec2 connection given credentials imported from config
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    return boto.ec2.connect_to_region(aws_cfg.get("aws", "region"),
                                      aws_access_key_id=aws_cfg.get("aws", "access_key_id"),
                                      aws_secret_access_key=aws_cfg.get("aws", "secret_access_key"))

def connect_to_rds():
    """
    return an rds connection given credentials imported from config
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    return boto.rds.connect_to_region(aws_cfg.get("aws", "region"),
                                      aws_access_key_id=aws_cfg.get("aws", "access_key_id"),
                                      aws_secret_access_key=aws_cfg.get("aws", "secret_access_key"))

def connect_to_s3():
    """
    return an s3 connection given credentials imported from config
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    return boto.s3.connect_to_region(aws_cfg.get("aws", "region"),
                                      aws_access_key_id=aws_cfg.get("aws", "access_key_id"),
                                      aws_secret_access_key=aws_cfg.get("aws", "secret_access_key"))

def connect_to_iam():
    """
    return an IAM connection given credentials imported from config
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    return boto.iam.connect_to_region("universal",
                                      aws_access_key_id=aws_cfg.get("aws", "access_key_id"),
                                      aws_secret_access_key=aws_cfg.get("aws", "secret_access_key"))

def connect_to_r53():
    """
    return a route53 connection given credentials imported from config
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    return boto.route53.connect_to_region('universal',
                                          aws_access_key_id=aws_cfg.get("aws", "access_key_id"),
                                          aws_secret_access_key=aws_cfg.get("aws", "secret_access_key"))

def setup_aws_account():
    """
    Attempts to setup key pairs and ec2 security groups provided in aws.cfg
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    ec2 = connect_to_ec2()

    # Check to see if specified keypair already exists.
    # If we get an InvalidKeyPair.NotFound error back from EC2,
    # it means that it doesn't exist and we need to create it.
    try:
        key_name = aws_cfg.get('aws', 'key_name')
        key = ec2.get_all_key_pairs(keynames=[key_name])[0]
        print "key name {} already exists".format(key_name)
    except ec2.ResponseError, error:
        if error.code == 'InvalidKeyPair.NotFound':
            print 'Creating keypair: %s' % key_name
            # Create an SSH key to use when logging into instances.
            key = ec2.create_key_pair(aws_cfg.get("aws", "key_name"))

            # Make sure the specified key_dir actually exists.
            # If not, create it.
            key_dir = aws_cfg.get("aws", "key_dir")
            key_dir = os.path.expanduser(key_dir)
            key_dir = os.path.expandvars(key_dir)
            if not os.path.isdir(key_dir):
                os.mkdir(key_dir, 0700)

            # AWS will store the public key but the private key is
            # generated and returned and needs to be stored locally.
            # The save method will also chmod the file to protect
            # your private key.
            try:
                key.save(key_dir)
            except boto.exception.BotoClientError, error:
                print "can't save key. deleting"
                if ''.join(key_dir + '/' + key_name + ".pem") + " already exists," in error.message:
                    key.delete()
                    os.remove(''.join(key_dir + '/' + key_name + ".pem"))
            try:
                subprocess.Popen('ssh-add {}'.format(''.join(key_dir + '/' + key_name + ".pem")), shell=True)
            except Exception:
                print "ssh-add failed"
                key.delete()
                raise
        else:
            raise

    # Check to see if specified security group already exists.
    # If we get an InvalidGroup.NotFound error back from EC2,
    # it means that it doesn't exist and we need to create it.
    try:
        group = ec2.get_all_security_groups(groupnames=[aws_cfg.get("aws", "group_name")])[0]
    except ec2.ResponseError, error:
        if error.code == 'InvalidGroup.NotFound':
            print 'Creating Security Group: %s' % aws_cfg.get("aws", "group_name")
            # Create a security group to control access to instance via SSH.
            group = ec2.create_security_group(aws_cfg.get("aws", "group_name"),
                                              'A group that allows SSH and Web access')
        else:
            raise

    # Add a rule to the security group to authorize SSH traffic
    # on the specified port.
    for port in ["80", "443", aws_cfg.get("aws", "ssh_port")]:
        try:
            group.authorize('tcp', port, port, "0.0.0.0/0")
        except ec2.ResponseError, error:
            if error.code == 'InvalidPermission.Duplicate':
                print 'Security Group: %s already authorized' % aws_cfg.get("aws", "group_name")
            else:
                raise

    # rds authorization
    rds = connect_to_rds()
    try:
        rdsgroup = rds.get_all_dbsecurity_groups(groupname=aws_cfg.get("aws", "group_name"))[0]
    except rds.ResponseError, error:
        if error.code == 'DBSecurityGroupNotFound':
            print 'Creating DB Security Group: %s' % aws_cfg.get("aws", "group_name")
            try:
                rdsgroup = rds.create_dbsecurity_group(aws_cfg.get("aws", "group_name"),
                                                              'A group that allows Webserver access')
                rdsgroup.authorize(ec2_group=group)
            except Exception, error:
                print _red('Error occured while create security group "%s": %s') %(aws_cfg.get("aws", "group_name"), str(error))
                print _yellow('Rolling back!')
                rds.delete_dbsecurity_group(aws_cfg.get("aws", "group_name"))
                return
        else:
            raise

def remove_dns_entries(name, app_type):
    """
    Remove route53 entries that point to ec2 instance with provided named alias
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)

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

def setup_route53_dns(name, app_type):
    """
    Creates Route53 DNS entries for given ec2 instance and app_type
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)

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
            apex = zone.add_a(app_zone_name, ec2ip, ttl=300)
            while apex.status != 'INSYNC':
                print _yellow("creation of A record: " + _green(app_zone_name + " " + ec2ip) + _yellow(" is ") + _red(apex.status))
                apex.update()
                time.sleep(10)
            print _green("creation of A record: " + app_zone_name + " is now " + apex.status)
        except Exception as error:
            if 'already exists' in error.message:
                print _yellow("address record " + _green(app_zone_name + " " + ec2ip) + _yellow(" already exists. skipping creation"))
            else:
                raise

    try:
        cname = zone.add_cname(app_host_name, ec2host, ttl=300, comment="expa " + app_type + " entry")
        while cname.status != 'INSYNC':
            print _yellow("creation of cname: " + _green(app_host_name) + _yellow(" is ") + _red(cname.status))
            cname.update()
            time.sleep(10)
        print _green("creation of cname: " + app_host_name + " is now " + cname.status)
    except Exception as error:
        if 'already exists' in error.message:
            print _yellow("cname record " + _green(app_host_name) + _yellow(" already exists. skipping creation"))
        else:
            raise

def setup_s3_logging_bucket(app_type):
    """
    Creates the S3 bucket for webserver log syncing
    """
    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)

    s3 = connect_to_s3()
    s3LogBucket = app_settings["DOMAIN_NAME"] + "-webserver-logs"
    s3StorageBucket = app_settings["DOMAIN_NAME"] + "-storage"
    for bucket in [ s3LogBucket, s3StorageBucket ]:
        try:
            print "creating {}".format(bucket) 
            s3.create_bucket('{}'.format(bucket), policy='private')
        except Exception, error:
            print error
            raise

    try:
        app_settings["S3_LOGGING_BUCKET"]
    except KeyError:
        app_settings["S3_LOGGING_BUCKET"] = s3LogBucket
        savesettings(app_settings, app_type + '_settings.json')

    try:
        app_settings["S3_STORAGE_BUCKET"]
    except KeyError:
        app_settings["S3_STORAGE_BUCKET"] = s3StorageBucket
        savesettings(app_settings, app_type + '_settings.json')

# DO NOT USE YET
def setup_instance_role():
    """
    Creates IAM instance role that allows writing to webserver logging bucket.
    TODO: Needs to be transactional.
    """
    try:
        app_settings
    except NameError:
        app_settings = loadsettings('app')

    BUCKET_POLICY = """{
    "Statement":[{
        "Effect":"Allow",
        "Action":["s3:*"],
        "Resource":["arn:aws:s3:::%s"]
        }
    ]}""" % app_settings["DOMAIN_NAME"] + "-webserver-logs"
    iam = connect_to_iam()
    try:
        iam.create_instance_profile('myinstanceprofile')
        iam.create_role('s3loggingRole')
        iam.add_role_to_instance_profile('myinstanceprofile', 's3loggingRole')
        iam.put_role_policy('s3loggingRole', 's3loggingPolicy', BUCKET_POLICY)
    except Exception:
        iam.remove_role_from_instance_profile('myinstanceprofile', 's3loggingRole')
        iam.delete_role_policy('s3loggingRole', 's3loggingPolicy')
        iam.list_role_policies('s3loggingRole')
        iam.delete_role('s3loggingRole')
        iam.delete_instance_profile('myinstanceprofile')
        raise

def load_aws_cfg():
    try:
        config = aws.read_config_file('aws.cfg')
        env.key_filename = os.path.expanduser(os.path.join(config.get("aws", "key_dir"),
                                                           config.get("aws", "key_name") + ".pem"))
        return config
    except Exception as error:
        print "aws.cfg not found. %s" % error
        return 1

def load_git_cfg():
    try:
        #git_cfg = Config(open('git.cfg'))
        git_cfg = aws.read_config_file('git.cfg')
        return git_cfg
    except Exception as error:
        print "git.cfg not found. %s" % error
        return 1
    
def install_requirements(release=None, app_type='app'):
    "Install the required packages from the requirements file using pip"
    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)

    if release is None:
        release = 'current'

    with cd('{path}'.format(path=app_settings["PROJECTPATH"])):
        run('./bin/pip install -q --upgrade distribute')
        run('./bin/pip install -q -r ./releases/{release}/requirements/{requirements_file}.txt'.format(release=release,
                                                                                                    requirements_file=app_settings["REQUIREMENTSFILE"]))

def migrate(app_type):
    "Update the database"
    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)

    with cd('{path}/releases/current/{app_name}'.format(path=app_settings["PROJECTPATH"], app_name=app_settings["APP_NAME"])):
        with settings(hide('running')):
            print _yellow('Running syncdb...')
            run("SECRET_KEY='{secretkey}' ../../../bin/python manage.py syncdb --noinput".format(secretkey=app_settings["DJANGOSECRETKEY"]))
            print _yellow('Running migrate...')
            run("SECRET_KEY='{secretkey}' ../../../bin/python manage.py migrate".format(secretkey=app_settings["DJANGOSECRETKEY"]))
            #run('../../../bin/python manage.py loaddata app/fixtures/')

def install_web(app_type):
    "Install web serving components"
    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)
    
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    sudo('mkdir -p {path}/tmp/ {path}/pid/ {path}/sock/'.format(path=app_settings["PROJECTPATH"]), warn_only=True)
    sudo('mkdir -p /var/log/nginx/{host_name}; \
          chown www-data /var/log/nginx/{host_name}'.format(host_name=app_settings["HOST_NAME"]))

    install_package('nginx')
    if os.path.exists('./keys/{{project_name}}.key') and os.path.exists('./keys/{{project_name}}.crt'):
        put('./keys/{{project_name}}.key', '/etc/ssl/private/', use_sudo=True)
        put('./keys/{{project_name}}.crt', '/etc/ssl/certs/', use_sudo=True)
        sudo('chown 700 /etc/ssl/private/{{project_name}}.key')
        sudo('chown 644 /etc/ssl/certs/{{project_name}}.crt')

    sudo('pip install -q uwsgi')
    with cd('{path}/releases/current'.format(path=app_settings["PROJECTPATH"])):
        sudo('cp ./config/uwsgi /etc/init.d/uwsgi')
        sudo('if [ ! -d /etc/uwsgi ]; then mkdir /etc/uwsgi ; fi')
        sudo('cp ./config/{app_type}-uwsgi.xml /etc/uwsgi/{app_name}-uwsgi.xml; \
              chown root:root /etc/uwsgi/{app_name}-uwsgi.xml; \
              chmod 600 /etc/uwsgi/{app_name}-uwsgi.xml'.format(app_type=app_type, app_name=app_settings["APP_NAME"]))

        sudo('cp ./config/nginx.conf /etc/nginx/')
        sudo('cp ./config/{app_type}-nginx.conf /etc/nginx/sites-enabled/{app_name}-nginx.conf; \
              chown root:root /etc/nginx/sites-enabled/{app_name}-nginx.conf; \
              chmod 600 /etc/nginx/sites-enabled/{app_name}-nginx.conf'.format(app_type=app_type, app_name=app_settings["APP_NAME"]))
        try:
            app_settings["S3_LOGGING_BUCKET"]
        except KeyError:
            setup_s3_logging_bucket(app_type)
            app_settings = loadsettings(app_type)
        sudo('mkdir -p /root/logrotate')
        sudo('mv ./config/root-crontab ./config/nginx-logrotate /root/logrotate/')
        sudo('mv ./config/s3cfg /root/.s3cfg; chown root:root /root/.s3cfg ; chmod 600 /root/.s3cfg')
        with settings(hide('running')):
            sudo('sed -i -e "s:<S3_LOGGING_BUCKET>:{s3_logging_bucket}/:g" /root/logrotate/nginx-logrotate'.format(s3_logging_bucket=app_settings["S3_LOGGING_BUCKET"]))
            sudo('sed -i -e "s:<ACCESS_KEY>:{access_key}:g" -e "s:<SECRET_KEY>:{secret_key}:g" /root/.s3cfg'.format(access_key=aws_cfg.get('aws', 'access_key_id'),
                                                                                                                    secret_key=aws_cfg.get('aws', 'secret_access_key')))
            sudo("sed -i -e 's:<DBNAME>:{dbname}:g' -e 's:<DBUSER>:{dbuser}:g' -e 's:<DBPASS>:{dbpass}:g' \
                -e 's:<DBHOST>:{dbhost}:g' -e 's:<DBPORT>:{dbport}:g' -e 's:<DJANGOSECRETKEY>:{djangosecretkey}:g' \
                -e 's:<DOMAIN_NAME>:{domain_name}:g' -e 's:<APP_NAME>:{app_name}:g' -e 's:<PROJECTPATH>:{projectpath}:g' -e 's:<HOST_NAME>:{hostname}:g' \
                -e 's:<AWS_ACCESS_KEY_ID>:{aws_access_key_id}:g' -e 's:<AWS_SECRET_ACCESS_KEY>:{aws_secret_access_key}:g' -e 's:<AWS_STORAGE_BUCKET_NAME>:{aws_storage_bucket_name}:g' \
                /etc/uwsgi/{app_name}-uwsgi.xml /etc/nginx/sites-enabled/{app_name}-nginx.conf".format(dbname=app_settings["DATABASE_NAME"], dbuser=app_settings["DATABASE_USER"],
                                                                       dbpass=app_settings["DATABASE_PASS"], dbhost=app_settings["DATABASE_HOST"],
                                                                       dbport=app_settings["DATABASE_PORT"], djangosecretkey=app_settings["DJANGOSECRETKEY"],
                                                                       domain_name=app_settings["DOMAIN_NAME"], app_name=app_settings["APP_NAME"],
                                                                       projectpath=app_settings["PROJECTPATH"], hostname=app_settings["HOST_NAME"],
                                                                       aws_access_key_id=aws_cfg.get('aws', 'access_key_id'), aws_secret_access_key=aws_cfg.get('aws', 'secret_access_key'),
                                                                       aws_storage_bucket_name=app_settings["S3_STORAGE_BUCKET"]))


        sudo('crontab -u root /root/logrotate/root-crontab')
    sudo('chmod 755 /etc/init.d/uwsgi')

def install_localdb_server(name, db_type):
    """
    Install db server on named instance of db_type
    """
    sethostfromname(name)

    try:
        app_settings
    except NameError:
        app_settings = loadsettings('app')

    try:
        app_settings["LOCAL_DB_SUPERUSER_PASS"]
    except KeyError:
        app_settings["LOCAL_DB_SUPERUSER_PASS"] = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for ii in range(32))
        savesettings(app_settings, 'app_settings.json')

    if db_type == 'mysql':
        with settings(hide('running', 'stdout')):
            sudo('echo mysql-server-5.5 mysql-server/root_password password {dbpass} | debconf-set-selections'.format(dbpass=app_settings["LOCAL_DB_SUPERUSER_PASS"]))
            sudo('echo mysql-server-5.5 mysql-server/root_password_again password {dbpass} | debconf-set-selections'.format(dbpass=app_settings["LOCAL_DB_SUPERUSER_PASS"]))
        install_package('mysql-server-5.5')
        sudo('/etc/init.d/mysql restart')
    elif db_type == 'postgresql':
        # TODO: deal with whiptail on postgres
        package_list = [ 'postgresql-9.3', 'postgresql-contrib-9.3', 'postgresql-server-dev-9.3', 'postgis', 'postgresql-9.3-postgis', 'postgresql-9.3-postgis-2.1-scripts' ]
        install_package(' '.join(package_list))
        with(settings(hide('running'))):
            put('./config/pg_hba.conf', '/etc/postgresql/9.3/main/pg_hba.conf', use_sudo=True)
        sudo('/etc/init.d/postgresql restart')
    time.sleep(15)

def start_webservers():
    sudo('/etc/init.d/nginx start')
    sudo('/etc/init.d/uwsgi start')

def collectremote(name, app_type, release=None):
    """
    Run django collect static on named instance for app_type
    """
    sethostfromname(name)
    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)

    with cd(app_settings["PROJECTPATH"]):
        run('./bin/python ./releases/{release}/{app_name}/manage.py collectstatic --settings=settings.production --noinput'.format(release=release, app_name=app_settings["APP_NAME"]))

def collectlocal():
    """
    Create deployable tarball.

    return: release number as a string
    """
    release = time.strftime('%Y%m%d%H%M%S')
    local("find . -name '*.pyc' -delete", capture=False)
    local('python ./{{project_name}}/manage.py collectstatic --noinput ')
    local('tar -cjf  {release}.tbz --exclude=keys/* --exclude=aws.cfg --exclude=settings.json --exclude=fab_hosts/* --exclude=.git --exclude={{project_name}}/media *'.format(release=release))
    return release

def symlink_current_release(release, app_type):
    "Symlink our current release"
    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)

    with cd('{path}'.format(path=app_settings["PROJECTPATH"])):
        run('rm releases/previous; mv releases/current releases/previous; ln -s {release} releases/current'.format(release=release))

def upload_tar_from_local(release=None, app_type='app'):
    "Create an archive from the current Git master branch and upload it"
    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)

    if release is None:
        release = collectlocal()

    run('mkdir -p {path}/releases/{release} {path}/packages'.format(path=app_settings["PROJECTPATH"], release=release))
    put('{release}.tbz'.format(release=release), '{path}/packages/'.format(path=app_settings["PROJECTPATH"], release=release))
    run('cd {path}/releases/{release} && tar xjf ../../packages/{release}.tbz'.format(path=app_settings["PROJECTPATH"], release=release))
    sudo('rm {path}/packages/{release}.tbz'.format(path=app_settings["PROJECTPATH"], release=release))
    local('rm {release}.tbz'.format(release=release))

def createlocaldb(app_type, db_type='mysql'):
    """
    Create a local mysql db on named instance with given app settings.
    """
    try:
        app_settings
    except NameError:
        app_settings = loadsettings('app')

    try:
        local_app_settings
    except NameError:
        local_app_settings = loadsettings(app_type)

    try:
        with settings(hide('running','warnings')):
            if db_type == 'mysql':
                sudo('mysqladmin -p{mysql_root_pass} create {dbname}'.format(mysql_root_pass=app_settings["LOCAL_DB_SUPERUSER_PASS"], dbname=local_app_settings["DATABASE_NAME"]), warn_only=True)
                sudo('mysql -uroot -p{mysql_root_pass} -e "GRANT ALL PRIVILEGES ON {dbname}.* to {dbuser}@\'localhost\' IDENTIFIED BY \'{dbpass}\'"'.format(mysql_root_pass=app_settings["LOCAL_DB_SUPERUSER_PASS"],
                                                                                                                                                            dbname=local_app_settings["DATABASE_NAME"],
                                                                                                                                                            dbuser=local_app_settings["DATABASE_USER"],
                                                                                                                                                            dbpass=local_app_settings["DATABASE_PASS"]))
            elif db_type == 'postgresql':
                # TODO: setup a postgres db
                with settings(hide('stdout')):
                    sudo('psql -c "CREATE USER {dbuser} WITH PASSWORD \'{dbpass}\'"'.format(dbuser=local_app_settings["DATABASE_USER"], dbpass=local_app_settings["DATABASE_PASS"]), user='postgres', warn_only=True)
                    sudo('createdb {dbname}'.format(dbname=local_app_settings["DATABASE_NAME"]), user='postgres', warn_only=True)
                    sudo('psql -c "GRANT ALL PRIVILEGES ON DATABASE {dbname} to {dbuser};"'.format(dbname=local_app_settings["DATABASE_NAME"], dbuser=local_app_settings["DATABASE_USER"]), user='postgres', warn_only=True)
                    sudo('psql -c "CREATE EXTENSION postgis; CREATE EXTENSION postgis_topology;" -d {dbname}'.format(dbname=local_app_settings["DATABASE_NAME"]), user='postgres', warn_only=True)
    except Exception as error:
        print error

def install_package(name):
    """ install a package using APT """
    with settings(hide('running', 'stdout'), warn_only=True):
        print _yellow('Installing package %s... ' % name),
        result = sudo('apt-get -qq -y --force-yes install %s' % name)
        if result.return_code != 0:
            print "apt-get failed: " + result
            raise SystemExit()
        else:
            print _green('[DONE]')

def update_apt():
    """ run apt-get update """
    with settings(hide('running', 'stdout'), warn_only=True):
        print _yellow('Updating APT cache... '),
        result = sudo('apt-get update')
        if result.return_code != 0:
            print "apt-get failed: " + result
            raise SystemExit()
        else:
            print _green('[DONE]')

def savesettings(appsettingsjson, settingsfile):
    #print _red("saving settings to: " + settingsfile)
    with open(settingsfile, "w") as settingsfile:
        settingsfile.write(json.dumps(appsettingsjson, indent=4, separators=(',', ': '), sort_keys=True))

def loadsettings(app_type):
    settingsfile = app_type + '_settings.json'

    try:
        with open(settingsfile, "r") as settingsfile:
            settingsjson = json.load(settingsfile)
    except Exception:
        settingsjson = generatedefaultsettings(app_type)
        savesettings(settingsjson, settingsfile)
    return settingsjson

def generatedefaultsettings(settingstype):
    if settingstype in ('expa_core', 'core', 'expacore'):
        app_settings = {"DATABASE_USER" : "expacore",
                        # RDS password limit is 41 characters and only printable chars. Felt weird so we'll make it 32.
                        "DATABASE_PASS" : ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for ii in range(32)),
                        "APP_NAME" : "expa_core",
                        "DATABASE_NAME" : "expacore",
                        "DATABASE_HOST" : "localhost",
                        "DATABASE_PORT" : "5432",
                        "DB_TYPE" : "postgresql",
                        "PROJECTPATH" : "/mnt/ym/expacore",
                        "REQUIREMENTSFILE" : "production",
                        "DOMAIN_NAME" : "test.expa.com",
                        "HOST_NAME" : "core.test.expa.com",
                        "INSTALLROOT" : "/mnt/ym",
                        "ADMIN_USER" : "coreadmin",
                        "ADMIN_EMAIL" : "coreadmin@expa.com",
                        "ADMIN_PASS" : ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for ii in range(16)),
                        "DJANGOSECRETKEY" : ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits + '@#$%^&*()') for ii in range(64))
                        }
    elif settingstype in ('expa_gis', 'gis', 'expagis'):
        app_settings = {"DATABASE_USER": "expagis",
                        # RDS password limit is 41 characters and only printable chars. Felt weird so we'll make it 32.
                        "DATABASE_PASS": ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for ii in range(32)),
                        "APP_NAME": "expa_gis",
                        "DATABASE_NAME": "expagis",
                        "DATABASE_HOST": "localhost",
                        "DATABASE_PORT": "5432",
                        "DB_TYPE" : "postgresql",
                        "PROJECTPATH" : "/mnt/ym/expagis",
                        "REQUIREMENTSFILE" : "production",
                        "DOMAIN_NAME" : "test.expa.com",
                        "HOST_NAME" : "gis.test.expa.com",
                        "INSTALLROOT" : "/mnt/ym",
                        "ADMIN_USER" : "gisadmin",
                        "ADMIN_EMAIL" : "gisadmin@expa.com",
                        "ADMIN_PASS" : ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for ii in range(16)),
                        "DJANGOSECRETKEY" : ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits + '@#$%^&*()') for ii in range(64))
                        }
    elif settingstype == 'blog':
        app_settings = {"DATABASE_USER": "{{project_name}}_blog",
                        # RDS password limit is 41 characters and only printable chars. Felt weird so we'll make it 32.
                        "DATABASE_PASS": ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for ii in range(32)),
                        "APP_NAME": "blog",
                        "DATABASE_NAME": "blog",
                        "DATABASE_HOST": "localhost",
                        "DATABASE_PORT": "3306",
                        "DB_TYPE" : "mysql",
                        "PROJECTPATH" : "/mnt/ym/blog",
                        "REQUIREMENTSFILE" : "production",
                        "DOMAIN_NAME" : "test.expa.com",
                        "HOST_NAME" : "blog.test.expa.com",
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
                        "DATABASE_PORT": "5432",
                        "DB_TYPE" : "postgresql",
                        "PROJECTPATH" : "/mnt/ym/{{project_name}}",
                        "REQUIREMENTSFILE" : "production",
                        "DOMAIN_NAME" : "test.expa.com",
                        "HOST_NAME" : "www.test.expa.com",
                        "INSTALLROOT" : "/mnt/ym",
                        "DJANGOSECRETKEY" : ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits + '@#$%^*()') for ii in range(64))
                        }
    return app_settings

def addtosshconfig(name, dns):
    """
    Add provided hostname and dns to ssh_config with config template below
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    ssh_slug = """
    Host {name}
    HostName {dns}
    Port 22
    User ubuntu
    IdentityFile {key_file_path}
    ForwardAgent yes
    """.format(name=name, dns=dns, key_file_path=os.path.join(os.path.expanduser(aws_cfg.get("aws", "key_dir")), aws_cfg.get("aws", "key_name") + ".pem"))
    if os.name == 'posix':
        try:
            with open(os.path.expanduser("~/.ssh/config"), "a+") as ssh_config:
                ssh_config.seek(0)
                if not dns in ssh_config.read():
                    ssh_config.seek(0, 2)
                    ssh_config.write("{}\n".format(ssh_slug))
        except Exception as error:
            print error

def removefromsshconfig(dns):
    """
    Remove ssh_slug containing provided name and dns from ssh_config
    """
    if os.name == 'posix':
        try:
            with open(os.path.expanduser("~/.ssh/config"), "r+") as ssh_config:
                lines = ssh_config.readlines()
                blockstart = substringindex(lines, dns)
                blockend = substringindex(lines, "ForwardAgent yes", blockstart)
                del(lines[blockstart-2:blockend+2])
                ssh_config.seek(0)
                ssh_config.write(''.join(lines))
                ssh_config.truncate()
        except Exception as error:
            print error

def sethostfromname(name):
    if env.host_string != '127.0.0.1':
        fabhostfile = open("fab_hosts/{}.txt".format(name))
        env.host_string = "ubuntu@{}".format(fabhostfile.readline().strip())

def substringindex(the_list, substring, offset=0):
    for sindex, sstring in enumerate(the_list):
        if (substring in sstring) and ( sindex >= offset):
            return sindex
    return -1
