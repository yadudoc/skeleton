========================
expa-deploy
========================

A common deployment framework to spin up vagrant or aws instances with a base django app.

To use this project follow these steps:

#. Create your working environment
#. Install Django
#. Create the new project using the django-two-scoops template
#. Use the Django admin to create the project
#. Use Vagrant to start up your dev environment
#. (optional) use fab to spin up AWS instances

*note: these instructions show creation of a project called "test_me".  You
should replace this name with the actual name of your project.*

Working Environment
===================

You have several options in setting up your working environment.  We recommend
using virtualenv to separate the dependencies of your project from your system's
python environment.  If on Linux or Mac OS X, you can also use virtualenvwrapper to help manage multiple virtualenvs across different projects.

Virtualenv Only
---------------

First, make sure you are using virtualenv (http://www.virtualenv.org). Once
that's installed, create your virtualenv::

    $ virtualenv test_me
    $ cd test_me
    $ soruce bin/activate

Installing Django
=================

To install Django in the new virtual environment, run the following command::

    $ pip install django

Creating your project
=====================

To create a new Django project called '**test_me**' using
django-twoscoops-project, run the following command::

    $ django-admin.py startproject --template=https://github.com/expa/expa-deploy/archive/master.zip --extension=py,rst,html --name=deploy/*,Vagrantfile test_me

Vagrant + VirtualBox
====================

Grab VirtualBox (https://www.virtualbox.org/wiki/Downloads) and Vagrant (http://downloads.vagrantup.com/)::

    $ vagrant plugin install vagrant-fabric
    $ cd test_me
    $ vagrant up

Acknowledgements
================

- Many thanks to Randall Degges for the inspiration to write the book and django-skel.
- All of the contributors_ to this project.

.. _contributors: https://github.com/twoscoops/django-twoscoops-project/blob/master/CONTRIBUTORS.txt
