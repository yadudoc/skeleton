#!/bin/bash
# script to setup demo on one ec2 instance and local mysql
source ~/.bash_profile
project_name=testproject
config_dir=~/tmp/configs

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

vagrant up

