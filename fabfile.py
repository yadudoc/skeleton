
import boto.ec2, boto.rds, boto.route53, boto.s3, boto.iam
import os, time, json, string, random, subprocess, calendar

from contextlib import contextmanager
from random import choice
from ConfigParser import SafeConfigParser

from boto.ec2.elb import HealthCheck
from boto.exception import S3ResponseError, BotoServerError
from boto.opsworks.exceptions import ValidationException
from fabric.operations import put
from fabric.api import env, local, sudo, run, cd, prefix
from fabric.api import task, settings
from fabric.colors import green as _green, yellow as _yellow
from fabric.colors import red as _red, blue as _blue
from fabric.context_managers import hide, shell_env

from progress.spinner import Spinner
from datetime import datetime, timedelta
from operator import itemgetter

OPSWORKS_SERVICE_ASSUME_ROLE_POLICY = json.dumps({
    'Statement': [{'Principal': {'Service': ['opsworks.amazonaws.com']},
                   'Effect': 'Allow',
                   'Action': ['sts:AssumeRole']}]})

OPSWORKS_SERVICE_ROLE_POLICY = json.dumps({
    'Statement': [{'Action': ['ec2:*', 'iam:PassRole',
                              'cloudwatch:GetMetricStatistics',
                              'elasticloadbalancing:*'],
                   'Effect': 'Allow',
                   'Resource': ['*']}]}
)

OPSWORKS_EC2_ASSUME_ROLE_POLICY = json.dumps({
    'Statement': [{'Principal': {'Service': ['ec2.amazonaws.com']},
                   'Effect': 'Allow',
                   'Action': ['sts:AssumeRole']}]})

OPWORKS_INSTANCE_THEMES = ['Baked_Goods', 'Clouds', 'Europe_Cities', 'Fruits',
                           'Greek_Deities_and_Titans', 'Legendary_creatures_from_Japan', 'Planets_and_Moons',
                           'Roman_Deities', 'Scottish_Islands', 'US_Cities', 'Wild_Cats']

OPSWORKS_CONFIG_MANAGER = {"Name": "Chef",
                           "Version": "11.4"}


#-----FABRIC TASKS-----------
@task
def create_rds(name, app_type, engine_type=None, security_groups=None):
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

    rds = connect_to_rds()

    try:
        groups = rds.get_all_dbsecurity_groups(groupname=aws_cfg.get("aws", "group_name"))
    except rds.ResponseError:
        setup_aws_account()
        groups = rds.get_all_dbsecurity_groups(groupname=aws_cfg.get("aws", "group_name"))

    if security_groups is not None:
        groups = groups.append(security_groups)

    if engine_type is None:
        engine_type = app_settings["DB_TYPE"]

    print(_green("Creating RDS instance {name}...".format(name=name)))

    try:
        print groups
        dbinstance = rds.create_dbinstance(id=name,
                                           allocated_storage=aws_cfg.get("rds", "rds_storage_size"),
                                           instance_class=aws_cfg.get("rds", "rds_instance_type"),
                                           engine=engine_type,
                                           master_username=app_settings["DATABASE_USER"],
                                           master_password=app_settings["DATABASE_PASS"],
                                           db_name=app_settings["DATABASE_NAME"],
                                           security_groups=groups)
    except BotoServerError as e:
        if e.code == "DBInstanceAlreadyExists":
            dbinstance = rds.get_all_dbinstances(instance_id=name)[0]
        else:
            print _red('Error occured while provisioning the RDS instance  %s' % str(e))
            raise e
    except Exception, e:
        print _red('Error occured while provisioning the RDS instance  %s' % str(e))
        raise e

    spinner = Spinner(_yellow('Waiting for rdsInstance to start... '))
    status = dbinstance.update()
    while status != 'available':
        spinner.next()
        time.sleep(1)
        status = dbinstance.update()

    if status == 'available':
        print _green('\nNew rdsInstance %s accessible at %s on port %d') % (dbinstance.id, dbinstance.endpoint[0], dbinstance.endpoint[1])

    dbhost = str(dbinstance.endpoint[0])
    dbport = str(dbinstance.endpoint[1])

    app_settings["DATABASE_HOST"] = dbhost
    app_settings["DATABASE_PORT"] = dbport
    app_settings["OPSWORKS_CUSTOM_JSON"]["deploy"][app_settings["APP_NAME"]]["environment_variables"]["DBHOST"] = dbhost
    app_settings["OPSWORKS_CUSTOM_JSON"]["deploy"][app_settings["APP_NAME"]]["environment_variables"]["DBPORT"] = dbport
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
    spinner = Spinner(_yellow("...Creating EC2 instance... "))

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
    conn.create_tags([instance.id], {"Name": name})
    if tag:
        instance.add_tag(tag)

    while instance.state != u'running':
        spinner.next()
        time.sleep(10)
        instance.update()

    print(_green("\nInstance state: %s" % instance.state))
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
            with settings(hide('running', 'stdout')):
                env.user = 'ubuntu'
                run('uname')
            connectivity = True
        except Exception:
            time.sleep(5)
    return instance.public_dns_name


@task
def create_stack(stackName, app_type):
    """
    creates an OpsWorks stack with details from app settings JSON
    """
    if app_type in ['core', 'expacore', 'expa_core']:
        app_type = 'core'

    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)

    try:
        aws_cfg
    except NameError:
        try:
            aws_cfg = load_aws_cfg()
        except Exception, error:
            print(_red("error loading config. please provide an AWS conifguration based on aws.cfg-dist to proceed. %s" % error))
            return 1

    try:
        git_cfg
    except NameError:
        try:
            git_cfg = load_git_cfg()
        except Exception, error:
            print(_red("error loading config. please provide a github conifguration based on git.cfg-dist to proceed. %s" % error))
            return 1

    stackName = stackName.lower()
    key_file_path = os.path.expanduser(git_cfg.get('git', 'key_dir')) + '/' + git_cfg.get('cookbooks', 'deploy_key')
    key_file_path = os.path.expandvars(key_file_path)
    with open(key_file_path, "r") as key_file:
        cookbooks_deploy_key = key_file.read()

    key_file_path = os.path.expanduser(git_cfg.get('git', 'key_dir')) + '/' + git_cfg.get(app_type, 'deploy_key')
    key_file_path = os.path.expandvars(key_file_path)
    with open(key_file_path, "r") as key_file:
        app_deploy_key = key_file.read()

    key_file_path = os.path.expanduser(aws_cfg.get('aws', 'key_dir')) + '/' + aws_cfg.get('aws', 'opsworks_public_key')
    key_file_path = os.path.expandvars(key_file_path)
    with open(key_file_path, "r") as key_file:
        opsworks_public_key = key_file.read()

    cookbooks_source = {"Url": "%s" % git_cfg.get('cookbooks', 'repo_url'),
                        "Type": "git",
                        "SshKey": cookbooks_deploy_key}

    recipes = {"Setup": ["bootstrap::default"],
               "Deploy": ["app::default"]}

    app_source = {"Url": "%s" % git_cfg.get(app_type, 'repo_url'),
                  "Type": "git",
                  "SshKey": app_deploy_key}

    arns = create_opsworks_roles()

    create_s3_buckets(app_type)
    opsworks = connect_to_opsworks()
    stacks = opsworks.describe_stacks()

    try:
        opsworks.create_user_profile(iam_user_arn=arns['user_arn'], ssh_public_key=opsworks_public_key)
    except ValidationException, error:
        if error.message == 'User ARN already exists':
            opsworks.update_user_profile(iam_user_arn=arns['user_arn'], ssh_public_key=opsworks_public_key)
        else:
            print error
            return 1

    if stackName in [stack['Name'] for stack in stacks['Stacks']]:
        foundStacks = [(stack['Name'], stack['StackId']) for stack in stacks['Stacks']]
        for foundStack in foundStacks:
            if foundStack[0] == stackName:
                print(_red("%s: %s already exists. please choose another stack name" % (foundStack[0], foundStack[1])))
        return 1

    try:
        stack = opsworks.create_stack(name=stackName, region=aws_cfg.get('aws', 'region'),
                                      service_role_arn=arns['serviceRole'], default_instance_profile_arn=arns['instanceProfile'],
                                      default_os='Ubuntu 12.04 LTS', hostname_theme=choice(OPWORKS_INSTANCE_THEMES),
                                      configuration_manager=OPSWORKS_CONFIG_MANAGER, custom_json=json.dumps(app_settings["OPSWORKS_CUSTOM_JSON"], sort_keys=True, indent=4, separators=(',', ': ')),
                                      use_custom_cookbooks=True, custom_cookbooks_source=cookbooks_source, default_ssh_key_name=aws_cfg.get("aws", "key_name"),
                                      default_root_device_type='ebs')

        opsworks.set_permission(stack_id=stack['StackId'], iam_user_arn=arns['user_arn'], allow_ssh=True, allow_sudo=True)
    except Exception, error:
        print error
        print json.dumps(app_settings["OPSWORKS_CUSTOM_JSON"], sort_keys=True, indent=4, separators=(',', ': '))
        return 1

    ec2 = connect_to_ec2()
    webserver_sg = ec2.get_all_security_groups(groupnames=['AWS-OpsWorks-Web-Server'])
    layer = opsworks.create_layer(stack_id=stack['StackId'], type='custom', name=app_settings["APP_NAME"], shortname=app_settings["APP_NAME"], custom_recipes=recipes,
                                  enable_auto_healing=True, auto_assign_elastic_ips=False, auto_assign_public_ips=True, custom_security_group_ids=[webserver_sg[0].id])

    elb_name = stackName + '-elb'
    lb = create_elb(name=elb_name, app_type=app_type)

    opsworks.attach_elastic_load_balancer(elastic_load_balancer_name=lb.name, layer_id=layer['LayerId'])

    if app_type == 'app':
        appDomains = [app_settings["HOST_NAME"], app_settings["DOMAIN_NAME"]]
    else:
        appDomains = [app_settings["HOST_NAME"]]
    app = opsworks.create_app(stack_id=stack['StackId'], name=app_settings["APP_NAME"], type='static', app_source=app_source,
                              domains=appDomains)

    print(_green("created stack with following info"))
    print(_yellow("stack name/id: %s/%s" % (stackName, stack['StackId'])))
    print(_yellow("layer name/id: %s/%s" % (app_settings["APP_NAME"], layer['LayerId'])))
    print(_yellow("app name/id: %s/%s" % (app_settings["APP_NAME"], app['AppId'])))

    zones = random.sample([zone.name for zone in ec2.get_all_zones()], 2)

    add_instance(stackName=stackName, layerName=app_settings["APP_NAME"], zone=zones[0])
    add_instance(stackName=stackName, layerName=app_settings["APP_NAME"], zone=zones[1])

    rds_instance_name = stackName + '-' + app_settings["HOST_NAME"].replace('.', '-') + '-db'
    rds = connect_to_rds()
    if app_settings["DATABASE_HOST"] == "localhost":
        try:
            create_rds(name=rds_instance_name, app_type=app_type, engine_type=app_settings['DB_TYPE'])
        except Exception:
            print(_red("rds creation failed. deleting stack with no RDS instance"))
            delete_stack(stackName)
    else:
        try:
            rds.get_all_dbinstances(instance_id=app_settings["DATABASE_HOST"].split('.')[0])
        except BotoServerError, error:
            if error.code == 'DBInstanceNotFound':
                create_rds(name=rds_instance_name, app_type=app_type, engine_type=app_settings['DB_TYPE'])
            else:
                print error

    try:
        rds.authorize_dbsecurity_group(group_name=aws_cfg.get('aws', 'group_name'),
                                       ec2_security_group_owner_id=webserver_sg[0].owner_id, ec2_security_group_name='AWS-OpsWorks-Web-Server')
    except BotoServerError, error:
        if error.code == 'AuthorizationAlreadyExists':
            pass
        else:
            print error

    # update stack with new custom_json updated by create_rds and create_s3_buckets
    app_settings = loadsettings(app_type)
    opsworks.update_stack(stack_id=stack['StackId'], custom_json=json.dumps(app_settings["OPSWORKS_CUSTOM_JSON"], sort_keys=True, indent=4, separators=(',', ': ')))

    if raw_input("shall we start the opsworks instance(s)? (y/n) ").lower() == "y":
        start_instance(stackName)
    else:
        print(_green("use fab start_instance:%s to start the stack" % stackName))


@task
def add_instance(stackName, layerName, zone=None):
    """
    adds an ec2 instance to an OpsWorks Stack/Layer combo
    """
    try:
        aws_cfg
    except NameError:
        try:
            aws_cfg = load_aws_cfg()
        except Exception, error:
            print(_red("error loading config. please provide an AWS conifguration based on aws.cfg-dist to proceed. %s" % error))
            return 1

    stackName = stackName.lower()
    opsworks = connect_to_opsworks()
    stacks = opsworks.describe_stacks()
    stackId = [stack['StackId'] for stack in stacks['Stacks'] if stack['Name'] == stackName]
    layers = opsworks.describe_layers(stack_id=stackId[0])
    layerIds = [layer['LayerId'] for layer in layers['Layers'] if layer['Name'] == layerName]

    if zone is None:
        ec2 = connect_to_ec2()
        zones = [zone.name for zone in ec2.get_all_zones()]
        zone = choice(zones)

    instance = opsworks.create_instance(stack_id=stackId[0], layer_ids=layerIds, instance_type=aws_cfg.get(aws_cfg.get('aws', 'instance_size'), 'instance_type'), availability_zone=zone)
    instanceName = opsworks.describe_instances(instance_ids=[instance['InstanceId']])['Instances'][0]['Hostname']
    print(_yellow("instance name/id/az: %s/%s/%s" % (instanceName, instance['InstanceId'], zone)))
    return {"name": instanceName, "id": instance['InstanceId'], "zone": zone}


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
                    #remove_dns_entries(name, 'app')

# TODO: wait until rds is terminated


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

    rds = connect_to_rds()
    try:
        dbinstances = rds.get_all_dbinstances(instance_id=name)
    except BotoServerError, e:
        if e.code == "DBInstanceNotFound":
            print(_red(e.message))
            return 1
    for instance in dbinstances:
        if "terminated" in str(instance.status):
            print "instance {} is already terminated".format(instance.id)
            continue
        if raw_input("terminate {instance}? (y/n) ".format(instance=instance.id)).lower() == "y":
            spinner = Spinner(_yellow("Terminating {}".format(instance.id)))
            if instance.status == 'available':
                rds.delete_dbinstance(id=instance.id, skip_final_snapshot=True)
            elif instance.status == 'deleting':
                print(_green("instance already terminating"))
            while instance.status == 'deleting':
                spinner.next()
                time.sleep(1)
                instance.update()
            print(_green("Terminated"))


@task
def start_instance(stackName, instanceName=None):
    """
    start given instance id/name in given stack id/name or stop all instances in a stack
    """
    control_instance(stackName=stackName, action='start', instanceName=instanceName)


@task
def stop_instance(stackName, instanceName=None):
    """
    stop given instance id/name in given stack id/name or stop all instances in a stack
    """
    control_instance(stackName=stackName, action='stop', instanceName=instanceName)


@task
def delete_stack(stackName):
    """
    deletes an OpsWorks stack with details from app settings JSON
    """
    try:
        aws_cfg
    except NameError:
        try:
            aws_cfg = load_aws_cfg()
        except Exception, error:
            print(_red("error loading config. please provide an AWS conifguration based on aws.cfg-dist to proceed. %s" % error))
            return 1

    stackName = stackName.lower()
    opsworks = connect_to_opsworks()
    stacks = opsworks.describe_stacks()
    stackIds = [stack['StackId'] for stack in stacks['Stacks'] if stack['Name'] == stackName]
    for stackId in stackIds:
        prompt = _green("shall we remove stack: ") + _yellow("%s/%s? (y/n) ") % (stackName, str(stackId).encode('ascii', 'replace'))
        answer = raw_input(prompt)
        if answer.lower() == 'y':
            stop_instance(stackName=stackName)
            apps = opsworks.describe_apps(stack_id=stackId)
            appIds = [app['AppId'] for app in apps['Apps']]
            instances = opsworks.describe_instances(stack_id=stackId)
            instanceIds = [instance['InstanceId'] for instance in instances['Instances']]
            for instanceId in instanceIds:
                opsworks.delete_instance(instance_id=instanceId, delete_elastic_ip=True, delete_volumes=True)
            for appId in appIds:
                opsworks.delete_app(appId)
            opsworks.delete_stack(stackId)


@task
def get_ssl_certs():
    """
    return a list of all  ssl certs
    """
    try:
        aws_cfg
    except NameError:
        try:
            aws_cfg = load_aws_cfg()
        except Exception, error:
            print(_red("error loading config. please provide an AWS conifguration based on aws.cfg-dist to proceed. %s" % error))
            return 1

    iam = connect_to_iam()
    certs = iam.get_all_server_certs()['list_server_certificates_response']['list_server_certificates_result']['server_certificate_metadata_list']
    for cert in certs:
        print cert['server_certificate_name']
    return certs


@task
def delete_ssl_cert(certname):
    """
    deletes the nameed iam server cert
    """
    try:
        aws_cfg
    except NameError:
        try:
            aws_cfg = load_aws_cfg()
        except Exception, error:
            print(_red("error loading config. please provide an AWS conifguration based on aws.cfg-dist to proceed. %s" % error))
            return 1

    iam = connect_to_iam()
    iam.delete_server_cert(certname)


@task
def getdeploys(deploymentState=None, stack=None):
    """
    returns a list of opsworks deployments in the given state. default is to return all deployments
    """
    try:
        aws_cfg
    except NameError:
        try:
            aws_cfg = load_aws_cfg()
        except Exception, error:
            print error
            return 1

    opsworks = connect_to_opsworks()
    ostacks = getstacks(stackName=stack)

    for ostack in ostacks:
        # print "calling describe_deployments"
        allDeployments = opsworks.describe_deployments(stack_id=ostack['stackid'])
        if deploymentState is None:
            deployments = [deployment for deployment in allDeployments['Deployments']]
        else:
            deployments = [deployment for deployment in allDeployments['Deployments'] if deployment['Status'] == deploymentState]
        if len(deployments) > 0:
            output = []
            # print "calling describe_instances"
            instanceNames = {instance['InstanceId']: instance['Hostname'] for instance in opsworks.describe_instances(stack_id=ostack['stackid'])['Instances']}
            # print "calling describe_apps"
            appNames = {app['AppId']: app['Name'] for app in opsworks.describe_apps(stack_id=ostack['stackid'])['Apps']}
            stackName = ostack['name'] or stack

            header = ['Stack', 'App', 'Command', 'Status', 'DeployUser', 'InstanceNames', 'Started', 'Finished', 'Duration']
            # print _green("Stack \t App \t Command \t Status \t Started \t Finished")
            for deployment in deployments:
                # print json.dumps(deployment, indent=4, separators=(',', ': '), sort_keys=True)
                deployedInstanceNames = []
                if 'InstanceIds' in deployment.keys():
                    deployedInstanceNames = [instanceNames[instanceId] for instanceId in deployment['InstanceIds']]

                if 'AppId' in deployment.keys():
                    appName = appNames[deployment['AppId']]
                else:
                    appName = 'None'

                if 'CompletedAt' in deployment.keys():
                    finished = utc_to_local(datetime.strptime(deployment['CompletedAt'], '%Y-%m-%dT%H:%M:%S+00:00'))
                else:
                    finished = 'None'
                if 'IamUserArn' in deployment.keys():
                    deployUser = deployment['IamUserArn'].replace('arn:aws:iam::', '')
                else:
                    deployUser = 'aws'

                if 'Duration' in deployment.keys():
                    duration = deployment['Duration']
                else:
                    duration = 'None'

                # example: 2014-03-06T22:53:19+00:00
                started = utc_to_local(datetime.strptime(deployment['CreatedAt'], '%Y-%m-%dT%H:%M:%S+00:00'))
                command = deployment['Command']['Name']
                args = deployment['Command']['Args']

                if deployment['Status'] == 'successful':
                    outputColor = _green
                elif deployment['Status'] == 'running':
                    outputColor = _yellow
                elif deployment['Status'] == 'failed':
                    outputColor = _red

                output.append({'Stack': stackName, 'App': appName, 'Command': '%s(%s)' % (command, args), 'Status': deployment['Status'], 'DeployUser': deployUser, 'InstanceNames': ','.join(deployedInstanceNames), 'Started': started, 'Finished': finished, 'Duration': duration, 'color': outputColor})
            print format_as_table(output, header=header, keys=header)
        else:
            print _green("no deployments in state: %s" % deploymentState)


@task
def getstacks(stackName=None):
    """
    returns a list of opsworks stacks
    """
    try:
        aws_cfg
    except NameError:
        try:
            aws_cfg = load_aws_cfg()
        except Exception, error:
            print error
            return 1

    opsworks = connect_to_opsworks()
    stacks = opsworks.describe_stacks()
    myStacks = []
    if stacks['Stacks'] != []:
        for stack in stacks['Stacks']:
            if stackName is None:
                myStacks.append({'name': stack['Name'], 'stackid': stack['StackId']})
            else:
                if stackName == stack['Name']:
                    myStacks.append({'name': stack['Name'], 'stackid': stack['StackId']})
        for myStack in myStacks:
            print _green("%s: %s" % (myStack['name'], myStack['stackid']))
        return myStacks
    else:
        print(_green("no stacks defined"))
        return None


@task
def getec2instances():
    """
    Returns a list of all ec2 instances
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    # We don't need to do this?
    # Get a list of instance IDs for the ELB.
    # instances = []
    # conn = connect_to_elb()
    # for elb in conn.get_all_load_balancers():
    #     instances.extend(elb.instances)

    # Get the instance IDs for the reservations.
    conn = connect_to_ec2()
    #reservations = conn.get_all_instances([i.id for i in instances])
    reservations = conn.get_all_instances()
    instance_ids = []
    for reservation in reservations:
        for i in reservation.instances:
            instance_ids.append(i.id)

    # Get the public CNAMES for those instances.
    taggedhosts = []
    for host in conn.get_all_instances(instance_ids):
        for instance in host.instances:
            if instance.state == 'running':
                if 'opsworks:instance' in instance.tags.keys():
                    taggedhosts.extend([[instance.public_dns_name, instance.tags['opsworks:instance'], instance.instance_type]])
                    isOpsworksInstance = True
                    iam = connect_to_iam()
                    opsworks = connect_to_opsworks()
                    user_arn = iam.get_user()['get_user_response']['get_user_result']['user']['arn']
                    ssh_user = opsworks.describe_user_profiles(iam_user_arns=[user_arn])['UserProfiles'][0]['SshUsername']
                else:
                    taggedhosts.extend([[instance.public_dns_name, instance.tags['Name'], instance.instance_type]])
                    isOpsworksInstance = False
                    ssh_user = 'ubuntu'
        taggedhosts.sort()  # Put them in a consistent order, so that calling code can do hosts[0] and hosts[1] consistently.

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
        addtosshconfig(name=taggedhost[1], dns=taggedhost[0], ssh_user=ssh_user, isOpsworksInstance=isOpsworksInstance)


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
    rdsinstances.sort()  # Put them in a consistent order, so that calling code can do hosts[0] and hosts[1] consistently.

    if not any(rdsinstances):
        print "no rds instances found"
    else:
        for rdsinstance in rdsinstances:
            print rdsinstance.id
    return rdsinstances


@task
def updatestack(stackName, jsonFile):
    """
    read Opsworks chef json from file and update given stack name
    """

    try:
        with open(os.path.join(os.path.expanduser(jsonFile)), "r") as chefJsonFile:
            chefJson = json.load(chefJsonFile)
    except IOError, e:
        raise e

    print _green("updating opsworks stack %s with json from %s..." % (stackName, jsonFile))
    updateOpsworksStackJson(stackName, chefJson)


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
    package_list = ['libjpeg8-dev', 'language-pack-en', 'aptitude', 'git-core', 'ntpdate']
    if app_type == 'blog':
        package_list.extend(['php5-fpm', 'php5-gd', 'php5-json', 'php5-xcache', 'php5-mysql', 'php5-mcrypt', 'php5-imap', 'php5-geoip', 'php5-sqlite', 'php5-curl', 'php5-cli', 'php5-gd', 'php5-intl', 'php-pear', 'php5-imagick', 'php5-imap', 'php5-mcrypt', 'php5-memcache', 'php5-ming', 'php5-ps', 'php5-pspell', 'php5-recode', 'php5-snmp', 'php5-sqlite', 'php5-tidy', 'php5-xmlrpc', 'php5-xsl', 'nginx'])
    else:
        package_list.extend(['python-setuptools', 'gcc', 'git-core', 'libxml2-dev', 'libxslt1-dev', 'python-virtualenv', 'python-dev', 'python-lxml', 'libcairo2', 'libpango1.0-0', 'libgdk-pixbuf2.0-0', 'libffi-dev', 'libmysqlclient-dev'])

    with settings(hide('stdout')):
        if app_settings["DB_TYPE"] == 'mysql':
            package_list.extend(['mysql-client'])
            sudo('aptitude -y build-dep python-mysqldb')
        elif app_settings["DB_TYPE"] == 'postgres':
            package_list.extend(['postgresql-client-common', 'postgresql-client-9.3'])
            sudo('aptitude -y build-dep python-psycopg2')
    if app_settings["APP_NAME"] == 'expa_gis':
        package_list.extend(['postgis'])

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
    sudo('pip install -q --upgrade s3cmd')

    if app_settings["DATABASE_HOST"] == 'localhost':
        install_localdb_server(name, app_settings["DB_TYPE"])


@task
def deploy_opsworks(stackName, command, recipes=None, instanceName=None):
    """
    creates an opsworks deployment for given stackName and command
    """
    deploymentCommand = {
        'Name': '%s' % command
    }
    stackName = stackName.lower()
    opsworks = connect_to_opsworks()
    stacks = opsworks.describe_stacks()
    stackIds = [stack['StackId'] for stack in stacks['Stacks'] if stack['Name'] == stackName]
    if stackIds != []:
        for stackId in stackIds:
            if command == 'deploy':
                apps = opsworks.describe_apps(stack_id=stackId)
                appIds = [app['AppId'] for app in apps['Apps']]
                for appId in appIds:
                    deployment = opsworks.create_deployment(stack_id=stackId, app_id=appId, command=deploymentCommand)
            elif 'execute_recipe' in command:
                instances = opsworks.describe_instances(stackId)
                if instanceName is None:
                    instanceIds = [instance['InstanceId'] for instance in instances['Instances']]
                else:
                    instanceIds = [instance['InstanceId'] for instance in instances['Instances'] if instance['Hostname'] == instanceName]
                deploymentCommand['Name'] = 'execute_recipes'
                deploymentCommand['Args'] = {}
                deploymentCommand['Args']['recipes'] = [recipes]
                # print json.dumps(deploymentCommand, indent=4, separators=(',', ': '), sort_keys=True)
                deployment = opsworks.create_deployment(stack_id=stackId, instance_ids=instanceIds, command=deploymentCommand)
            else:
                deployment = opsworks.create_deployment(stack_id=stackId, command=deploymentCommand)
    else:
        print(_red("stack: %s not found" % stackName))
        return 1
    spinner = Spinner(_yellow("deployment %s: running... " % deployment['DeploymentId']))
    status = opsworks.describe_deployments(deployment_ids=[deployment['DeploymentId']])['Deployments'][0]['Status']
    while status == 'running':
        spinner.next()
        time.sleep(1)
        status = opsworks.describe_deployments(deployment_ids=[deployment['DeploymentId']])['Deployments'][0]['Status']
    if status != 'successful':
        print(_red("\ndeployment %s: %s" % (deployment['DeploymentId'], status)))
    else:
        print(_green("\ndeployment %s: %s" % (deployment['DeploymentId'], status)))
    return deployment


@task
def deployapp(name, app_type):
    """
    Deploy app_name module to instance with name alias
    """
    sethostfromname(name)
    try:
        app_settings
    except NameError:
        app_settings = loadsettings('app')

    try:
        aws_cfg
    except NameError:
        try:
            aws_cfg = load_aws_cfg()
        except Exception, error:
            print(_red("error loading config. please provide an AWS conifguration based on aws.cfg-dist to proceed. %s" % error))
            return 1

    try:
        git_cfg
    except NameError:
        try:
            git_cfg = load_git_cfg()
        except Exception, error:
            print(_red("error loading config. please provide a github conifguration based on git.cfg-dist to proceed. %s" % error))
            return 1

    if app_type in ('expa_core', 'core', 'expacore', 'expa_gis', 'gis'):
        release = time.strftime('%Y%m%d%H%M%S')
    else:
        release = collectlocal(app_type)

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
            put('{key_dir}/{key}'.format(key_dir=git_cfg.get("git", "key_dir"), key=git_cfg.get("git", app_type + "_deploy_key")), '~/.ssh/id_rsa', mode=0600)
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
    try:
        app_settings["S3_STORAGE_BUCKET"]
    except KeyError:
        create_s3_buckets(app_type)
        app_settings = loadsettings(app_type)
    symlink_current_release(release, app_type)
    install_requirements(release, app_type)
    if app_settings["APP_NAME"] in ('expa_core', 'core', 'expacore', 'expa_gis'):
        with cd('{}'.format(app_settings["PROJECTPATH"])):
            collectremote(name, app_type, release)
            migrate(app_type)
            with settings(hide('running')):
                with shell_env(DJANGO_SETTINGS_MODULE='settings.production',
                               DBNAME=app_settings["DATABASE_NAME"],
                               DBUSER=app_settings["DATABASE_USER"],
                               DBPASS=app_settings["DATABASE_PASS"],
                               DBHOST=app_settings["DATABASE_HOST"],
                               DBPORT=app_settings["DATABASE_PORT"],
                               DOMAIN_NAME=app_settings["DOMAIN_NAME"],
                               SECRET_KEY=app_settings["DJANGOSECRETKEY"],
                               AWS_ACCESS_KEY_ID=aws_cfg.get('aws', 'access_key_id'),
                               AWS_SECRET_ACCESS_KEY=aws_cfg.get('aws', 'secret_access_key'),
                               AWS_STORAGE_BUCKET_NAME=app_settings["S3_STORAGE_BUCKET"]
                               ):
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
        create_route53_ec2_dns(name, app_type)


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
                                                                                                                                                                                                                           blog_admin=app_settings["ADMIN_USER"],
                                                                                                                                                                                                                           blog_admin_email=app_settings["ADMIN_EMAIL"],
                                                                                                                                                                                                                           blog_pass=app_settings["ADMIN_PASS"]))
    sudo('rm -rf /home/ubuntu/.wp-cli')
    sudo('chown -R www-data:www-data {path}'.format(path=app_settings["PROJECTPATH"]))
    restart(name)
    create_route53_ec2_dns(name, 'blog')


@task
def localdev():
    """
    Deploy app to local vagrant. For use with vagrant up and provided VagrantFile
    """
    try:
        app_settings
    except NameError:
        app_settings = loadsettings('app')

    env.user = 'vagrant'
    env.group = 'vagrant'
    env.target = 'dev'
    env.development = 'true'

    with settings(hide('running')):
        sudo('echo "LANGUAGE=en_US.UTF-8" > /etc/default/locale')
        sudo('echo "LANG=en_US.UTF-8" >> /etc/default/locale')
        sudo('echo "LC_ALL=en_US.UTF-8" >> /etc/default/locale')
    bootstrap(env.host_string, 'app')
    sudo('chown -R {user}:{group} {path}'.format(path=app_settings["INSTALLROOT"], user=env.user, group=env.group))
    with cd('{}'.format(app_settings["PROJECTPATH"])):
        run('virtualenv --distribute .')
    install_requirements()
    print(_yellow("--creating db...--"))
    createlocaldb('app', app_settings["DB_TYPE"])

    with settings(hide('running')):
        sudo('echo "alias lserver=\'cd {projectpath} ; source bin/activate; python releases/current/{app_name}/manage.py runserver 0.0.0.0:8000\'" > /etc/profile.d/lserver.sh'.format(projectpath=app_settings["PROJECTPATH"], app_name=app_settings["APP_NAME"]))
        sudo('echo "alias lsync=\'cd {projectpath} ; source bin/activate; python releases/current/{app_name}/manage.py syncdb\'" > /etc/profile.d/lsync.sh'.format(projectpath=app_settings["PROJECTPATH"], app_name=app_settings["APP_NAME"]))
        sudo('echo "alias lmigrate=\'cd {projectpath} ; source bin/activate; python releases/current/{app_name}/manage.py migrate\'" > /etc/profile.d/lmigrate.sh'.format(projectpath=app_settings["PROJECTPATH"], app_name=app_settings["APP_NAME"]))
        run('if [ `grep lserver.sh ~/.bashrc >/dev/null 2>&1 ; echo $?` -eq 1 ]; then echo "source /etc/profile.d/lserver.sh" >> ~/.bashrc ; fi')
        run('if [ `grep lsync.sh ~/.bashrc >/dev/null 2>&1 ; echo $?` -eq 1 ]; then echo "source /etc/profile.d/lsync.sh" >> ~/.bashrc ; fi')
        run('if [ `grep lmigrate.sh ~/.bashrc >/dev/null 2>&1 ; echo $?` -eq 1 ]; then echo "source /etc/profile.d/lmigrate.sh" >> ~/.bashrc ; fi')
        sudo('if [ `grep "GRUB_RECORDFAIL_TIMEOUT=0" /etc/default/grub >/dev/null 2>&1 ; echo $?` -eq 1 ]; then echo "GRUB_RECORDFAIL_TIMEOUT=0" >> /etc/default/grub && update-grub2; fi')
    print(_green("--dev env ready. run vagrant ssh and lserver to start dev server--"))


@task
def restart(name):
    """
    Reload app server/nginx
    """
    sethostfromname(name)

    with settings(hide('running'), warn_only=True):
        sudo('if [ -x /etc/init.d/php5-fpm ]; then if [ "$( /etc/init.d/php5-fpm status > /dev/null 2>&1 ; echo $? )" = "3" ]; then /etc/init.d/php5-fpm start ; else /etc/init.d/php5-fpm reload ; fi ; fi')
        sudo('if [ -x /etc/init.d/uwsgi ]; then if [ "$( /etc/init.d/uwsgi status > /dev/null 2>&1 ; echo $? )" = "3" ]; then /etc/init.d/uwsgi start ; else touch /etc/uwsgi/*.xml ; fi; fi')
        sudo('if [ -x /etc/init.d/nginx ]; then if [ "$( /etc/init.d/nginx status > /dev/null 2>&1 ; echo $? )" = "3" ]; then /etc/init.d/nginx start ; else /etc/init.d/nginx reload ; fi ; fi')

#----------HELPER FUNCTIONS-----------


@contextmanager
def _virtualenv():
    """
    Activate virtual environment
    """
    with prefix(env.activate):
        yield

# aws


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


def connect_to_opsworks():
    """
    return an OpsWorks connection given credentials imported from config
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    return boto.connect_opsworks(aws_access_key_id=aws_cfg.get("aws", "access_key_id"),
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
                print _red('Error occured while create security group "%s": %s') % (aws_cfg.get("aws", "group_name"), str(error))
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


def create_route53_ec2_dns(name, app_type):
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


def create_route53_elb_dns(elb_name, app_type):
    """
    creates dns entries for given elb name/app_type combo
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)

    elb = connect_to_elb()
    r53 = connect_to_r53()

    lb = elb.get_all_load_balancers(load_balancer_names=elb_name)[0]
    app_zone_name = app_settings["DOMAIN_NAME"] + "."
    app_host_name = app_settings["HOST_NAME"] + "."

    print _green("Creating DNS for " + elb_name + " and app_type " + app_type)
    if r53.get_zone(app_zone_name) is None:
        print _yellow("creating zone " + _green(app_zone_name))
        zone = r53.create_zone(app_zone_name)
    else:
        # print _yellow("zone " + _green(app_zone_name) + _yellow(" already exists. skipping creation"))
        zone = r53.get_zone(app_zone_name)

    records = r53.get_all_rrsets(zone.id)

    if app_type == 'app':
        try:
            change = records.add_change('CREATE', zone.name, 'A', ttl=300, alias_hosted_zone_id=lb.canonical_hosted_zone_name_id, alias_dns_name=lb.canonical_hosted_zone_name)
            change.add_value('ALIAS %s (%s)' % (lb.canonical_hosted_zone_name, lb.canonical_hosted_zone_name_id))
            change_id = records.commit()['ChangeResourceRecordSetsResponse']['ChangeInfo']['Id'].split('/')[-1]
            status = r53.get_change(change_id)['GetChangeResponse']['ChangeInfo']['Status']
            spinner = Spinner(_yellow('[%s]waiting for route53 change to coalesce... ' % zone.name))
            while status != 'INSYNC':
                spinner.next()
                time.sleep(1)
                status = r53.get_change(change_id)['GetChangeResponse']['ChangeInfo']['Status']
            print(_green('\n[%s]route53 change coalesced' % zone.name))
        except Exception as error:
            if 'already exists' in error.message:
                # print _yellow("address record " + _green(app_zone_name + " " + lb.canonical_hosted_zone_name) + _yellow(" already exists. skipping creation"))
                pass
            else:
                raise

    try:
        change = records.add_change('CREATE', app_host_name, 'A', ttl=300, alias_hosted_zone_id=lb.canonical_hosted_zone_name_id, alias_dns_name=lb.canonical_hosted_zone_name)
        change.add_value('ALIAS %s (%s)' % (lb.canonical_hosted_zone_name, lb.canonical_hosted_zone_name_id))
        change_id = records.commit()['ChangeResourceRecordSetsResponse']['ChangeInfo']['Id'].split('/')[-1]
        status = r53.get_change(change_id)['GetChangeResponse']['ChangeInfo']['Status']
        spinner = Spinner(_yellow('[%s]waiting for route53 change to coalesce... ' % app_host_name))
        while status != 'INSYNC':
            spinner.next()
            time.sleep(1)
            status = r53.get_change(change_id)['GetChangeResponse']['ChangeInfo']['Status']
        print(_green('\n[%s]route53 change coalesced' % app_host_name))
    except Exception as error:
        if 'already exists' in error.message:
            print _yellow("cname record " + _green(app_host_name) + _yellow(" already exists. skipping creation"))
        else:
            raise

# TODO: set bucket policy to allow ec2 instance role to sync to log dir
# TODO: set bucket policy to allow ec2 instance role to r/w storage bucket


def create_s3_buckets(app_type):
    """
    Creates the S3 bucket for webserver log syncing
    """
    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)

    s3 = connect_to_s3()
    s3LogBucket = app_settings["HOST_NAME"].replace('.', '-') + "-logs"
    try:
        s3.get_bucket(s3LogBucket)
    except S3ResponseError:
        try:
            s3.create_bucket(s3LogBucket, policy='private')
        except Exception, error:
            print error
            raise

    s3StorageBucket = app_settings["HOST_NAME"].replace('.', '-') + "-" + app_type + "-storage"
    try:
        s3.get_bucket(s3StorageBucket)
    except S3ResponseError:
        try:
            s3.create_bucket(s3StorageBucket, policy='public-read')
        except Exception, error:
            print error
            raise

    try:
        app_settings["S3_LOGGING_BUCKET"]
    except KeyError:
        app_settings["S3_LOGGING_BUCKET"] = s3LogBucket
        app_settings["OPSWORKS_CUSTOM_JSON"]["deploy"][app_settings["APP_NAME"]]["environment_variables"]["AWS_LOGGING_BUCKET_NAME"] = s3LogBucket
        savesettings(app_settings, app_type + '_settings.json')

    try:
        app_settings["S3_STORAGE_BUCKET"]
    except KeyError:
        app_settings["S3_STORAGE_BUCKET"] = s3StorageBucket
        app_settings["OPSWORKS_CUSTOM_JSON"]["deploy"][app_settings["APP_NAME"]]["environment_variables"]["AWS_STORAGE_BUCKET_NAME"] = s3StorageBucket
        savesettings(app_settings, app_type + '_settings.json')


def create_opsworks_roles():
    """
    Creates IAM role/instance profiles for opsworks control
    """
    iam = connect_to_iam()

    try:
        service_role_arn = iam.create_role(role_name='aws-opsworks-service-role', assume_role_policy_document=OPSWORKS_SERVICE_ASSUME_ROLE_POLICY)['create_role_response']['create_role_result']['role']['arn']
    except BotoServerError:
        service_role_arn = iam.get_role(role_name='aws-opsworks-service-role')['get_role_response']['get_role_result']['role']['arn']
    iam.put_role_policy(role_name='aws-opsworks-service-role', policy_name='aws-opsworks-service-policy', policy_document=OPSWORKS_SERVICE_ROLE_POLICY)

    try:
        iam.create_role(role_name='aws-opsworks-ec2-role', assume_role_policy_document=OPSWORKS_EC2_ASSUME_ROLE_POLICY)
    except BotoServerError:
        pass

    try:
        instance_profile_arn = iam.create_instance_profile('aws-opsworks-ec2-role-instance-profile')['create_instance_profile_response']['create_instance_profile_result']['instance_profile']['arn']
    except BotoServerError:
        instance_profile_arn = iam.get_instance_profile('aws-opsworks-ec2-role-instance-profile')['get_instance_profile_response']['get_instance_profile_result']['instance_profile']['arn']

    try:
        iam.add_role_to_instance_profile('aws-opsworks-ec2-role-instance-profile', 'aws-opsworks-ec2-role')
    except BotoServerError, error:
        if "InstanceSessionsPerInstanceProfile" in error.message:
            pass
        else:
            print error
            raise

    user = iam.get_user()
    user_arn = user['get_user_response']['get_user_result']['user']['arn']
    return {"serviceRole": service_role_arn, "instanceProfile": instance_profile_arn, "user_arn": user_arn}


def create_elb(name, app_type):
    """
    creates an elb with the given name and app settings ...duh
    """
    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)

    certificate_name = name + '-' + app_settings['ELB_SSL_CERT_PATH'].split('/')[-1].split('.')[0]
    key_file_path = os.path.expanduser(app_settings['ELB_SSL_KEY_PATH'])
    key_file_path = os.path.expandvars(key_file_path)
    with open(key_file_path, "r") as key_file:
        ssl_key = key_file.read()

    cert_file_path = os.path.expanduser(app_settings['ELB_SSL_CERT_PATH'])
    cert_file_path = os.path.expandvars(cert_file_path)
    with open(cert_file_path, "r") as cert_file:
        ssl_cert = cert_file.read()

    iam = connect_to_iam()
    elb = connect_to_elb()
    ec2 = connect_to_ec2()

    try:
        iam.upload_server_cert(cert_name=certificate_name, cert_body=ssl_cert, private_key=ssl_key)
    except BotoServerError, e:
        if e.code == 'EntityAlreadyExists':
            pass
        else:
            raise
    except Exception, e:
        raise

    cert_arn = iam.get_server_certificate(certificate_name)['get_server_certificate_response']['get_server_certificate_result']['server_certificate']['server_certificate_metadata']['arn']
    zones = [zone.name for zone in ec2.get_all_zones()]
    listeners = [(80, 80, 'http'), (443, 80, 'https', cert_arn)]

    try:
        lb = elb.create_load_balancer(name=name, zones=zones, listeners=listeners)
    except BotoServerError, e:
        if e.code == 'CertificateNotFound':
            # for some reason IAM returns before the cert is actually available. sleep a bit and retry
            spinner = Spinner(_green("IAM is lame and we need to wait for the cert arn to propagate and retry... "))
            for i in range(5):
                spinner.next(i)
                time.sleep(1)
            print ""
            lb = elb.create_load_balancer(name=name, zones=zones, listeners=listeners)
        elif e.code == 'DuplicateLoadBalancerName':
            print "something went wrong. we don't know what to do yet..."
            raise
        else:
            print e
            raise
    except Exception, e:
        print e
        raise
    hc = HealthCheck(interval=30, target='TCP:80', healthy_threshold=2, timeout=5, unhealthy_threshold=10)
    lb.configure_health_check(hc)
    return lb


def control_instance(stackName, action, instanceName=None):
    """
    start/stop given instance id/name in given stack id/name or stop all instances in a stack
    """
    try:
        aws_cfg
    except NameError:
        try:
            aws_cfg = load_aws_cfg()
        except Exception, error:
            print(_red("error loading config. please provide an AWS conifguration based on aws.cfg-dist to proceed. %s" % error))
            return 1

    stackName = stackName.lower()
    opsworks = connect_to_opsworks()
    stacks = opsworks.describe_stacks()
    stackId = [stack['StackId'] for stack in stacks['Stacks'] if stack['Name'] == stackName]
    if stackId == []:
        print(_red("stack %s not found" % stackName))
        return 1
    instances = opsworks.describe_instances(stack_id=stackId[0])['Instances']
    if instanceName is not None:
        instances = [instance for instance in instances if instance['Hostname'] == instanceName]

    ec2 = connect_to_ec2()
    for instance in instances:
        if action == 'start':
            print(_green("starting instance: %s" % instance['Hostname']))
            try:
                opsworks.start_instance(instance_id=instance['InstanceId'])
            except ValidationException:
                pass
            myinstance = opsworks.describe_instances(instance_ids=[instance['InstanceId']])['Instances'][0]
            spinner = Spinner(_yellow("[%s]Waiting for reservation " % myinstance['Hostname']))
            while myinstance['Status'] == 'requested':
                spinner.next()
                time.sleep(1)
                myinstance = opsworks.describe_instances(instance_ids=[instance['InstanceId']])['Instances'][0]
            print(_green("\n[%s]OpsWorks instance status: %s" % (myinstance['Hostname'], myinstance['Status'])))
            ec2Instance = ec2.get_only_instances(instance_ids=[myinstance['Ec2InstanceId']])[0]
            spinner = Spinner(_yellow("[%s]Booting ec2 instance " % myinstance['Hostname']))
            while ec2Instance.state != u'running':
                spinner.next()
                time.sleep(1)
                ec2Instance.update()
            print(_green("\n[%s]ec2 Instance state: %s" % (myinstance['Hostname'], ec2Instance.state)))
            spinner = Spinner(_yellow("[%s]Running OpsWorks setup " % myinstance['Hostname']))
            while myinstance['Status'] != 'online':
                if myinstance['Status'] == 'setup_failed':
                    print(_red("\n[%s]OpsWorks instance failed" % myinstance['Hostname']))
                    return 1
                spinner.next()
                time.sleep(1)
                myinstance = opsworks.describe_instances(instance_ids=[instance['InstanceId']])['Instances'][0]
            print(_green("\n[%s]OpsWorks Instance state: %s" % (myinstance['Hostname'], myinstance['Status'])))
            getec2instances()
        elif action == 'stop':
            if 'Ec2InstanceId' in instance.keys():
                print(_green("Stopping instance %s" % instance['Hostname']))
                opsworks.stop_instance(instance_id=instance['InstanceId'])
                ec2Instance = ec2.get_only_instances(instance_ids=[instance['Ec2InstanceId']])[0]
                spinner = Spinner(_yellow("[%s]Waiting for ec2 instance to stop " % instance['Hostname']))
                while ec2Instance.state != u'stopped':
                    spinner.next()
                    time.sleep(1)
                    ec2Instance.update()
                print(_green("\n[%s]ec2 Instance state: %s" % (instance['Hostname'], ec2Instance.state)))
                myinstance = opsworks.describe_instances(instance_ids=[instance['InstanceId']])['Instances'][0]
                spinner = Spinner(_yellow("[%s]Stopping OpsWorks Instance " % instance['Hostname']))
                while myinstance['Status'] != 'stopped':
                    spinner.next()
                    time.sleep(1)
                    myinstance = opsworks.describe_instances(instance_ids=[instance['InstanceId']])['Instances'][0]
                print(_green("\n[%s]OpsWorks Instance state: %s" % (instance['Hostname'], myinstance['Status'])))
            else:
                print(_green("%s in %s already stopped" % (instance['Hostname'], stackName)))
            try:
                print(_green("removing %s from ssh config..." % instance['PublicDns']))
                removefromsshconfig(dns=instance['PublicDns'])
            except Exception:
                pass


def updateOpsworksStackJson(stackName, chefJson):
    """
    update an Opsworks stack's custom json with given name and json
    """
    try:
        aws_cfg
    except NameError:
        try:
            aws_cfg = load_aws_cfg()
        except Exception, error:
            print(_red("error loading config. please provide an AWS conifguration based on aws.cfg-dist to proceed. %s" % error))
            return 1

    stack = getstacks(stackName=stackName)[0]
    if 'stackid' in stack.keys():
        opsworks = connect_to_opsworks()
        opsworks.update_stack(stack_id=stack['stackid'], custom_json=json.dumps(chefJson, sort_keys=True, indent=2, separators=(',', ': ')))
    else:
        print _red("no stack found with name %s" % stackName)


# config

def save_config_file(config, config_file_path):
    with open(config_file_path, 'w') as fp:
        config.write(fp)


def read_config_file(config_file_path):
    config = SafeConfigParser()
    with open(config_file_path) as fp:
        config.readfp(fp)
    return config


def save_aws_cfg(config):
    save_config_file(config, 'aws.cfg')


def load_aws_cfg():
    try:
        config = read_config_file('aws.cfg')
        env.key_filename = os.path.expanduser(os.path.join(config.get("aws", "key_dir"),
                                                           config.get("aws", "key_name") + ".pem"))
        return config
    except Exception as error:
        print(_red("---something went wrong when reading your aws.cfg file. aws access will be disabled. %s---" % error))
        raise


def load_git_cfg():
    try:
        git_cfg = read_config_file('git.cfg')
        return git_cfg
    except Exception as error:
        print(_red("---something went wrong when reading your git.cfg file. github access will be disabled. %s---" % error))
        raise


# deployment automation

def install_requirements(release=None, app_type='app'):
    "Install the required packages from the requirements file using pip"
    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)

    if release is None:
        release = 'current'

    requirements_file = 'production.txt'

    if 'development' in env.keys():
        if env.development == 'true':
            requirements_file = 'local.txt'

    with cd('{path}'.format(path=app_settings["PROJECTPATH"])):
        run('./bin/pip install -q --upgrade distribute')
        run('./bin/pip install -q -r ./releases/%s/requirements/%s' % (release, requirements_file))


def migrate(app_type):
    "Update the database"
    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)

    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    with cd('{path}/releases/current/{app_name}'.format(path=app_settings["PROJECTPATH"], app_name=app_settings["APP_NAME"])):
        with settings(hide('running')):
            print _yellow('Running syncdb...')
            with shell_env(DJANGO_SETTINGS_MODULE='settings.production',
                           DBNAME=app_settings["DATABASE_NAME"],
                           DBUSER=app_settings["DATABASE_USER"],
                           DBPASS=app_settings["DATABASE_PASS"],
                           DBHOST=app_settings["DATABASE_HOST"],
                           DBPORT=app_settings["DATABASE_PORT"],
                           DOMAIN_NAME=app_settings["DOMAIN_NAME"],
                           SECRET_KEY=app_settings["DJANGOSECRETKEY"],
                           AWS_ACCESS_KEY_ID=aws_cfg.get('aws', 'access_key_id'),
                           AWS_SECRET_ACCESS_KEY=aws_cfg.get('aws', 'secret_access_key'),
                           AWS_STORAGE_BUCKET_NAME=app_settings["S3_STORAGE_BUCKET"]
                           ):
                run("../../../bin/python manage.py syncdb  --noinput".format(secretkey=app_settings["DJANGOSECRETKEY"]))
                print _yellow('Running migrate...')
                run("../../../bin/python manage.py migrate".format(secretkey=app_settings["DJANGOSECRETKEY"]))
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
    sudo('mkdir -p /var/log/nginx/default /var/log/nginx/{host_name}; \
          chown www-data /var/log/nginx/{host_name}'.format(host_name=app_settings["HOST_NAME"]))

    install_package('nginx')
    if os.path.exists('./keys/{}.key'.format(app_settings["APP_NAME"])) and os.path.exists('./keys/{}.crt'.format(app_settings["APP_NAME"])):
        put('./keys/{}.key'.format(app_settings["APP_NAME"]), '/etc/ssl/private/', use_sudo=True)
        put('./keys/{}.crt'.format(app_settings["APP_NAME"]), '/etc/ssl/certs/', use_sudo=True)
        sudo('chmod 700 /etc/ssl/private/{app_name}.key; chown root:root /etc/ssl/private/{app_name}.key'.format(app_name=app_settings["APP_NAME"]))
        sudo('chmod 644 /etc/ssl/certs/{app_name}.crt; chown root:root /etc/ssl/certs/{app_name}.crt'.format(app_name=app_settings["APP_NAME"]))

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
            create_s3_buckets(app_type)
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
    elif db_type == 'postgres':
        # TODO: deal with whiptail on postgres
        package_list = ['postgresql-9.3', 'postgresql-contrib-9.3', 'postgresql-server-dev-9.3', 'postgis', 'postgresql-9.3-postgis', 'postgresql-9.3-postgis-2.1-scripts']
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

    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    with cd(app_settings["PROJECTPATH"]):
        with shell_env(DJANGO_SETTINGS_MODULE='settings.production',
                       DBNAME=app_settings["DATABASE_NAME"],
                       DBUSER=app_settings["DATABASE_USER"],
                       DBPASS=app_settings["DATABASE_PASS"],
                       DBHOST=app_settings["DATABASE_HOST"],
                       DBPORT=app_settings["DATABASE_PORT"],
                       DOMAIN_NAME=app_settings["DOMAIN_NAME"],
                       SECRET_KEY=app_settings["DJANGOSECRETKEY"],
                       AWS_ACCESS_KEY_ID=aws_cfg.get('aws', 'access_key_id'),
                       AWS_SECRET_ACCESS_KEY=aws_cfg.get('aws', 'secret_access_key'),
                       AWS_STORAGE_BUCKET_NAME=app_settings["S3_STORAGE_BUCKET"]
                       ):
            run('./bin/python ./releases/{release}/{app_name}/manage.py collectstatic --noinput'.format(release=release, app_name=app_settings["APP_NAME"]))


def collectlocal(app_type):
    """
    Create deployable tarball.

    return: release number as a string
    """
    try:
        app_settings
    except NameError:
        app_settings = loadsettings(app_type)

    release = time.strftime('%Y%m%d%H%M%S')
    local("find . -name '*.pyc' -delete", capture=False)
    local('python ./{}/manage.py collectstatic --noinput'.format(app_settings["APP_NAME"]))
    local('tar -cjf  {release}.tbz --exclude=keys/* --exclude=aws.cfg --exclude=*_settings.json --exclude=fab_hosts/* --exclude=.git --exclude={app_name}/media *'.format(release=release, app_name=app_settings["APP_NAME"]))
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
        release = collectlocal(app_type)

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
        with settings(hide('running', 'warnings')):
            if db_type == 'mysql':
                sudo('mysqladmin -p{mysql_root_pass} create {dbname}'.format(mysql_root_pass=app_settings["LOCAL_DB_SUPERUSER_PASS"], dbname=local_app_settings["DATABASE_NAME"]), warn_only=True)
                sudo('mysql -uroot -p{mysql_root_pass} -e "GRANT ALL PRIVILEGES ON {dbname}.* to {dbuser}@\'localhost\' IDENTIFIED BY \'{dbpass}\'"'.format(mysql_root_pass=app_settings["LOCAL_DB_SUPERUSER_PASS"],
                                                                                                                                                            dbname=local_app_settings["DATABASE_NAME"],
                                                                                                                                                            dbuser=local_app_settings["DATABASE_USER"],
                                                                                                                                                            dbpass=local_app_settings["DATABASE_PASS"]))
            elif db_type == 'postgres':
                # TODO: setup a postgres db
                with settings(hide('stdout')):
                    sudo('psql -c "CREATE USER {dbuser} WITH PASSWORD \'{dbpass}\' CREATEDB"'.format(dbuser=local_app_settings["DATABASE_USER"], dbpass=local_app_settings["DATABASE_PASS"]), user='postgres', warn_only=True)
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


# app settings

def savesettings(appsettingsjson, settingsfile):
    # print _red("saving settings to: " + settingsfile)
    with open(settingsfile, "w") as settingsfile:
        settingsfile.write(json.dumps(appsettingsjson, indent=4, separators=(',', ': '), sort_keys=True))


def loadsettings(app_type):
    settingsfile = app_type + '_settings.json'

    try:
        with open(settingsfile, "r") as settingsfile:
            settingsjson = json.load(settingsfile)
    except IOError:
        settingsjson = generatedefaultsettings(app_type)
        savesettings(settingsjson, settingsfile)
    except Exception, e:
        raise e
    return settingsjson


def generatedefaultsettings(settingstype):
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    install_root = '/srv/www'
    database_host = 'localhost'
    database_port = '5432'
    database_type = 'postgres'
    domain_name = 'test.expa.com'
    notification_email = 'ops@expa.com'

    elb_ssl_key_path = "./keys/expatest.key"
    elb_ssl_cert_path = "./keys/expatest.crt"

    aws_access_key_id = aws_cfg.get('aws', 'access_key_id') or ''
    aws_secret_access_key = aws_cfg.get('aws', 'secret_access_key') or ''

    if settingstype in ('expa_core', 'core', 'expacore'):
        database_user = 'expacore'
        database_name = 'expacore'

        fqdn = 'core.test.expa.com'
        app_name = 'expa_core'
        admin_user = 'coreadmin'
        admin_email = 'coreadmin@expa.com'
    elif settingstype in ('expa_gis', 'gis', 'expagis'):
        database_user = 'expagis'
        database_name = 'expagis'

        fqdn = 'gis.test.expa.com'
        app_name = 'expa_gis'
        admin_user = 'gisadmin'
        admin_email = 'gisadmin@expa.com'

    elif settingstype == 'blog':
        database_user = 'expablog'
        database_name = 'expablog'
        database_port = '3306'
        database_type = 'mysql'

        fqdn = 'blog.test.expa.com'
        app_name = 'blog'
        admin_user = 'expablog_admin'
        admin_email = 'expablog_admin@expa.com'
    else:
        database_user = 'app'
        database_name = 'app'

        fqdn = 'app.test.expa.com'
        app_name = None
        admin_user = 'app_admin'
        admin_email = 'app_admin@expa.com'

    print(_green("please enter details for app_type %s" % settingstype))
    install_root = raw_input('install root[%s]: ' % install_root) or install_root
    database_name = raw_input('db name[%s]: ' % database_name) or database_name
    database_user = raw_input('db user[%s]: ' % database_user) or database_user
    # RDS password limit is 41 characters and only printable chars. Felt weird so we'll make it 32.
    database_pass = raw_input('db password[random]: ') or ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for ii in range(32))

    fqdn = raw_input('fqdn for app[%s]: ' % fqdn) or fqdn
    domain_name = raw_input('base domain for app[%s]: ' % domain_name) or domain_name
    if app_name is None:
        app_name = raw_input('django app name[%s]: ' % app_name) or app_name

    elb_ssl_key_path = raw_input('ssl key path(rsa format)[%s]: ' % elb_ssl_key_path) or elb_ssl_key_path
    elb_ssl_cert_path = raw_input('ssl cert path(includes cert chain)[%s]: ' % elb_ssl_cert_path) or elb_ssl_cert_path

    admin_user = raw_input('admin user[%s]: ' % admin_user) or admin_user
    admin_email = raw_input('admin user email[%s]: ' % admin_email) or admin_email
    notification_email = raw_input('notification email(i.e. ops@)[%s]: ' % admin_email) or admin_email

    projectpath = install_root + '/' + app_name
    settingsModule = 'settings.production'
    djangosecretkey = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for ii in range(64))

    settingsjson = {"DATABASE_USER": database_user,
                    # RDS password limit is 41 characters and only printable chars. Felt weird so we'll make it 32.
                    "DATABASE_PASS": database_pass,
                    "APP_NAME": app_name,
                    "DATABASE_NAME": database_name,
                    "DATABASE_HOST": database_host,
                    "DATABASE_PORT": database_port,
                    "DB_TYPE": database_type,
                    "PROJECTPATH": projectpath,
                    "HOST_NAME": fqdn,
                    "DOMAIN_NAME": domain_name,
                    "INSTALLROOT": install_root,
                    "ADMIN_USER": admin_user,
                    "ADMIN_EMAIL": admin_email,
                    "ELB_SSL_CERT_PATH": elb_ssl_cert_path,
                    "ELB_SSL_KEY_PATH": elb_ssl_key_path,
                    "ADMIN_PASS": ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for ii in range(16)),
                    "DJANGOSECRETKEY": djangosecretkey,
                    "OPSWORKS_CUSTOM_JSON": {'deploy': {
                        app_name: {
                            'notification_email': notification_email,
                            'environment_variables': {
                                'DJANGO_SETTINGS_MODULE': settingsModule,
                                'NEWRELIC_ENVIRONMENT': '',
                                'DBNAME': database_name,
                                'DBUSER': database_user,
                                'DBPASS': database_pass,
                                'DBHOST': database_host,
                                'DBPORT': database_port,
                                'DOMAIN_NAME': domain_name,
                                'SECRET_KEY': djangosecretkey,
                                'AWS_ACCESS_KEY_ID': aws_access_key_id,
                                'AWS_SECRET_ACCESS_KEY': aws_secret_access_key,
                                'AWS_STORAGE_BUCKET_NAME': '',
                                'AWS_LOGGING_BUCKET_NAME': '',
                                'MANDRILL_API_KEY': ''
                            }
                        }
                    },
                        'aws': {
                            'access_key_id': aws_access_key_id,
                            'secret_access_key': aws_secret_access_key
                        },
                        'is_production': 'false',
                        'expa': {
                            'data': {
                                's3bucket': 'expadata',
                                'projectname': app_name,
                                'eventslogpath': '/var/log/expa/data'
                            }
                        },
                        'newrelic': {
                            'license_key': '',
                            'api_key': '',
                            'environment': '',
                            'production': {
                                'app_id': '',
                                'app_name': ''
                            },
                            'staging': {
                                'app_id': '',
                                'app_name': ''
                            }
                        }
                    }
                    }
    # print json.dumps(settingsjson, sort_keys=True, indent=4, separators=(',', ': '))
    return settingsjson


# utils

def addtosshconfig(name, dns, ssh_user='ubuntu', isOpsworksInstance=False):
    """
    Add provided hostname and dns to ssh_config with config template below
    """
    try:
        aws_cfg
    except NameError:
        aws_cfg = load_aws_cfg()

    if isOpsworksInstance is True:
        key_file = aws_cfg.get('aws', 'opsworks_public_key').replace('.pub', '')
    else:
        key_file = aws_cfg.get('aws', 'key_name') + '.pem'

    ssh_slug = """
    Host {name}
    HostName {dns}
    Port 22
    User {ssh_user}
    IdentityFile {key_file_path}
    ForwardAgent yes
    """.format(name=name, dns=dns, key_file_path=os.path.join(os.path.expanduser(aws_cfg.get("aws", "key_dir")), key_file), ssh_user=ssh_user)
    if os.name == 'posix':
        try:
            with open(os.path.expanduser("~/.ssh/config"), "a+") as ssh_config:
                ssh_config.seek(0)
                if name in ssh_config.read():
                    removefromsshconfig(name=name)
                    ssh_config.seek(0)
                if not dns in ssh_config.read():
                    ssh_config.seek(0, 2)
                    ssh_config.write("{}\n".format(ssh_slug))
        except Exception as error:
            print error


def removefromsshconfig(dns=None, name=None):
    """
    Remove ssh_slug containing provided name and dns from ssh_config
    """
    if os.name == 'posix':
        try:
            with open(os.path.expanduser("~/.ssh/config"), "r+") as ssh_config:
                lines = ssh_config.readlines()
                if name is None:
                    blockstart = substringindex(lines, dns)
                    blockend = substringindex(lines, "ForwardAgent yes", blockstart)
                    del(lines[blockstart - 2:blockend + 2])
                else:
                    blockstart = substringindex(lines, name)
                    blockend = substringindex(lines, "ForwardAgent yes", blockstart)
                    del(lines[blockstart - 1:blockend + 2])

                ssh_config.seek(0)
                ssh_config.write(''.join(lines))
                ssh_config.truncate()
        except Exception, e:
            print e


def sethostfromname(name):
    if env.host_string != '127.0.0.1':
        fabhostfile = open("fab_hosts/{}.txt".format(name))
        env.host_string = "ubuntu@{}".format(fabhostfile.readline().strip())


def substringindex(the_list, substring, offset=0):
    for sindex, sstring in enumerate(the_list):
        if (substring in sstring) and (sindex >= offset):
            return sindex
    return -1


def utc_to_local(utc_dt):
    # get integer timestamp to avoid precision lost
    timestamp = calendar.timegm(utc_dt.timetuple())
    local_dt = datetime.fromtimestamp(timestamp)
    assert utc_dt.resolution >= timedelta(microseconds=1)
    return local_dt.replace(microsecond=utc_dt.microsecond)


def format_as_table(data, keys, header=None, sort_by_key=None, sort_order_reverse=False):
    """Takes a list of dictionaries, formats the data, and returns
    the formatted data as a text table.

    Required Parameters:
        data - Data to process (list of dictionaries). (Type: List)
        keys - List of keys in the dictionary. (Type: List)

    Optional Parameters:
        header - The table header. (Type: List)
        sort_by_key - The key to sort by. (Type: String)
        sort_order_reverse - Default sort order is ascending, if
            True sort order will change to descending. (Type: Boolean)
    """
    # Sort the data if a sort key is specified (default sort order
    # is ascending)
    if sort_by_key:
        data = sorted(data,
                      key=itemgetter(sort_by_key),
                      reverse=sort_order_reverse)

    # If header is not empty, add header to data
    if header:
        # Get the length of each header and create a divider based
        # on that length
        header_divider = []
        for name in header:
            header_divider.append('-' * len(name))

        # Create a list of dictionary from the keys and the header and
        # insert it at the beginning of the list. Do the same for the
        # divider and insert below the header.
        header_divider = dict(zip(keys, header_divider))
        data.insert(0, header_divider)
        header = dict(zip(keys, header))
        data.insert(0, header)

    column_widths = []
    for key in keys:
        column_widths.append(max(len(str(column[key])) for column in data))

    # Create a tuple pair of key and the associated column width for it
    key_width_pair = zip(keys, column_widths)

    myFormat = ('%-*s ' * len(keys)).strip() + '\n'
    formatted_data = ''

    for element in data:
        if 'color' in element.keys():
            outputColor = element['color']
        else:
            outputColor = None
        data_to_format = []
        # Create a tuple that will be used for the formatting in
        # width, value myFormat
        for pair in key_width_pair:
            data_to_format.append(pair[1])
            data_to_format.append(element[pair[0]])
        if outputColor:
            formatted_data += outputColor(myFormat) % tuple(data_to_format)
        else:
            formatted_data += myFormat % tuple(data_to_format)
    return formatted_data
