========================
expa-deploy
========================

A common deployment framework to spin up vagrant or aws instances with a base django app.

To use this project follow these steps:

#. Create your working environment
#. Install Django
#. Create the new project using the skeleton template
#. Use the Django admin to create the project
#. Use Vagrant to start up your dev environment
#. Use Django to start up your app
#. (optional) use fab to spin up AWS instances

*note: these instructions show creation of a project called "testme".  You
should replace this name with the actual name of your project.*

Prerequisites
=============
#. Request addition as collaborator for expa/core github.com repo
#. Fork expa/core github.com repo
#. Create ssh key for use as deploy key (ssh-keygen -b 2048 -t rsa -f deploy -q -N "")
#. Upload contents to github.com of deploy.pub to deploy keys section of your forked repo
#. ssh-add your private key to your local ssh-agent
#. Ensure agent forwarding is on (ref: https://help.github.com/articles/using-ssh-agent-forwarding)

Working Environment
===================

You have several options in setting up your working environment.  We recommend
using virtualenv to separate the dependencies of your project from your system's
python environment.  If on Linux or Mac OS X, you can also use virtualenvwrapper to help manage multiple virtualenvs across different projects.

Virtualenv Only
---------------

First, make sure you are using virtualenv (http://www.virtualenv.org). Once
that's installed, create your virtualenv::

    $ virtualenv testme
    $ cd testme
    $ source bin/activate

Installing Django
=================

To install Django in the new virtual environment, run the following command::

    $ pip install django==1.5.1

Creating your project
=====================

To create a new Django project called '**testme**' using django-twoscoops-project, run the following command::

    $ django-admin.py startproject -v3 --template=https://github.com/expa/skeleton/archive/master.zip --extension=py,rst,html,conf,xml --name=Vagrantfile --name=crontab testme
    $ pip install -r requirements/local.txt

Vagrant + VirtualBox
====================

Grab VirtualBox (https://www.virtualbox.org/wiki/Downloads) and Vagrant (http://downloads.vagrantup.com/)::

    $ vagrant plugin install vagrant-fabric
    $ vagrant plugin install vagrant-vbguest
    $ cd testme
    $ vagrant up

Startup expa core
=================
To start expa core, use vagrant to enter the VM and django to start the server::

    $ vagrant ssh
    $ cd /mnt/ym/expacore
    $ source bin/activate
    $ python ./releases/current/expa_core/manage.py runserver 0.0.0.0:8001

Startup your app
====================
To start the **testme** app, use vagrant to enter the VM and django to start the server::

    $ vagrant ssh
    $ cd /mnt/ym/testme
    $ source bin/activate
    $ python ./releases/current/testme/manage.py runserver 0.0.0.0:8000

Acknowledgements
================

- Many thanks to Randall Degges for the inspiration to write the book and django-skel.
- All of the contributors_ to this project.

.. _contributors: https://github.com/twoscoops/django-twoscoops-project/blob/master/CONTRIBUTORS.txt
