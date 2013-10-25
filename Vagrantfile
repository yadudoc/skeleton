# -*- mode: ruby -*-
# vi: set ft=ruby :

# For development, it is not needed when run on the production environment.
Vagrant.require_plugin "vagrant-fabric"

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

box      = 'precise64'
url      = 'http://files.vagrantup.com/precise64.box'
hostname = 'vagrantdev'
ram      = '256'

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = box
  config.vm.synced_folder ".", "/mnt/ym/{{project_name}}/releases/current"
  config.vm.network :public_network

  config.vm.provider "virtualbox" do |v|
    v.customize ["modifyvm", :id, "--name", hostname]
    v.customize ["modifyvm", :id, "--memory", ram]
  end

  # Enable provisioning with fabric script, specifiying jobs you want execute,
  # and the path of fabfile.
  config.vm.provision :fabric do |fabric|
    fabric.fabfile_path = "./fabfile.py"
    fabric.tasks = ["dev", ]
  end
end
