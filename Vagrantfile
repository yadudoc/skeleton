# -*- mode: ruby -*-
# vi: set ft=ruby :

# For development, it is not needed when run on the production environment.
Vagrant.require_plugin "vagrant-fabric"

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

box      = 'precise64'
url      = 'http://files.vagrantup.com/precise64.box'
hostname = 'vagrantdev-{{project_name}}'
ram      = '256'

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = box
  config.vm.box_url = url
  config.vm.synced_folder ".", "/mnt/ym/{{project_name}}/releases/current"
  config.vm.network :public_network
  config.vm.network "forwarded_port", guest: 8000, host: 8000
  config.vm.network "forwarded_port", guest: 8001, host: 8001
  config.vm.network "forwarded_port", guest: 8002, host: 8002

  config.vm.provider "virtualbox" do |v|
    v.customize ["modifyvm", :id, "--name", hostname]
    v.customize ["modifyvm", :id, "--memory", ram]
  end

  #config.omnibus.chef_version = :latest
  
  #config.berkshelf.enabled = true
  #config.berkshelf.berksfile_path = "./chef_files/Berksfile"

  #config.vm.provision "chef_solo" do |chef|
  #    chef.encrypted_data_bag_secret_key_path = "chef_files/data_bag_key"
  #    chef.cookbooks_path = [ "chef_files/site-cookbooks", ]
  #    chef.roles_path = [ "chef_files/roles", ]
  #    chef.data_bags_path = [ "chef_files/data_bags", ]
  #    chef.add_role("localhost")
  #end
  # Enable provisioning with fabric script, specifiying jobs you want execute,
  # and the path of fabfile.
  config.vm.provision :fabric do |fabric|
    fabric.fabfile_path = "./fabfile.py"
    fabric.tasks = ["localdev", ]
  end
end
