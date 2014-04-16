========================
skeleton -- **CHANGE THIS README ONCE YOU START YOUR PROJECT!**
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
#. pip
#. virtualenv (optional: virtualenvwrapper)
#. setup git.cfg (based on git.cfg-dist)
#. setup aws.cfg (based on aws.cfg-dist)

Working Environment
===================
You have several options in setting up your working environment.  We recommend
using virtualenv to separate the dependencies of your project from your system's
python environment.  If on Linux or Mac OS X, you can also use virtualenvwrapper to help manage multiple virtualenvs across different projects.


Pip/Virtualenv/Virtualenvwrapper
---------------------------------
System-wide installation::

    $ sudo easy_install pip
    $ sudo pip install virtualenv
    $ sudo pip install virtualenvwrapper

Add the following to ~/.bash_profile::

    $ export WORKON_HOME=$HOME/.virtualenvs
    $ source /usr/local/bin/virtualenvwrapper.sh

Re-source your shell environment::

    $ source ~/.bash_profile

Virtualenv
-----------
First, make sure you are using virtualenv (http://www.virtualenv.org). Once
that's installed, create your virtualenv::

    $ mkvirtualenv testme
    $ workon testme

Installing Django
=================

To install Django in the new virtual environment, run the following command::

    $ pip install django==1.6

Creating your project
=====================

To create a new Django project called '**testme**' using django-twoscoops-project, run the following command::

    $ django-admin.py startproject -v3 --template=https://github.com/expa/skeleton/archive/master.zip --extension=py,rst,html,conf,xml --name=Vagrantfile --name=crontab testme
    $ pip install -r requirements/local.txt

Vagrant + VirtualBox
====================

Grab VirtualBox (https://www.virtualbox.org/wiki/Downloads) and Vagrant 1.3.5 (http://downloads.vagrantup.com/tags/v1.3.5)::

    $ vagrant plugin install vagrant-fabric
    $ vagrant plugin install vagrant-vbguest
    $ cd testme
    $ vagrant up

Startup your app
====================
To start the **testme** app, use vagrant to enter the VM and django to start the server::

    $ vagrant ssh
    $ cd /srv/www/testme
    $ source bin/activate
    $ python ./releases/current/testme/manage.py runserver 0.0.0.0:8000

Acknowledgements
================

- Many thanks to Randall Degges for the inspiration to write the book and django-skel.
- All of the contributors_ to this project.

.. _contributors: https://github.com/twoscoops/django-twoscoops-project/blob/master/CONTRIBUTORS.txt
