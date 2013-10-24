# -*- mode: ruby -*-
# vi: set ft=ruby :

# For development, it is not needed when run on the production environment.
#Vagrant.require_plugin "vagrant-fabric"

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "precise64"

  # Enable provisioning with fabric script, specifiying jobs you want execute,
  # and the path of fabfile.
  config.vm.provision :fabric do |fabric|
    fabric.fabfile_path = "./fabfile.py"
    fabric.tasks = ["collect","dev", ]
  end
end
