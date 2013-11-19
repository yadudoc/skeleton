#!/bin/bash
# script to setup test on three ec2 instances and RDS
source ~/.bash_profile
project_name=testproject
config_dir=~/tmp/configs
pushd . > /dev/null

if [ ! -d ~/tmp ];then mkdir ~/tmp ;fi
cd ~/tmp
if [ -n "$1" ]; then
	ENVDIR=$1
else
	ENVDIR=`mktemp -d ./${project_name}.XXXXXX` || exit 1
fi
echo "creating venv $ENVDIR..."
virtualenv $ENVDIR
cd $ENVDIR
source bin/activate
echo "starting django skeleton project..."
pip install django==1.5.1
django-admin.py startproject -v3 --template=https://github.com/expa/skeleton/archive/master.zip --extension=py,rst,html,conf,xml --name=Vagrantfile --name=crontab $project_name
cd $project_name
rcp ${config_dir}/aws.cfg ${config_dir}/git.cfg ${config_dir}/keys ./
pip install -r requirements/local.txt

fab \
create_rds:expacore-db-1,core,postgres \
create_rds:expagis-db-1,gis,postgres \
create_rds:expablog-db-1,blog,mysql \
create_rds:expatest-db-1,app,postgres \
create_ec2:expacore-1 \
create_ec2:expagis-1 \
create_ec2:expatest-2

fab \
bootstrap:expacore-1,core \
bootstrap:expacore-1,blog \
bootstrap:expagis-1,gis \
bootstrap:expatest-2,app \
deployapp:expacore-1,core \
deployapp:expagis-1,gis \
deploywp:expacore-1 \
deployapp:expatest-2,app

python ./tests/testapps.py
if [ $? -gt 0 ];then
	echo "something failed"
	exit 1
fi
