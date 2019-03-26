# -*- mode: ruby -*-
# vi: set ft=ruby :

# Specify a custom Vagrant box for the demo
DEMO_BOX_NAME = "ubuntu/bionic64"

# Vagrantfile API/syntax version.
# NB: Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = DEMO_BOX_NAME
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "1024"
    vb.cpus = "2"
  end
  config.vm.define "consul01" do |consul01|
    consul01.vm.hostname = "consul01"
    # Forward Consul web and api port 8500
    consul01.vm.network "forwarded_port", guest: 8500, host: 8511
      # n1.ssh.username = "root"
      # n1.ssh.password = "P@ssw0rd"
      # n1.ssh.keys_only = false
    #   n1.vm.provision "shell", inline: $script, env: {'CONSUL_DEMO_VERSION' => CONSUL_DEMO_VERSION}
    consul01.vm.network "private_network", ip: "172.20.20.11"
  end

  config.vm.define "consul02" do |consul02|
    consul02.vm.hostname = "consul02"
    # Forward Consul web and api port 8500
    consul02.vm.network "forwarded_port", guest: 8500, host: 8512
      # n2.ssh.username = "root"
      # n2.ssh.password = "P@ssw0rd"
      # n2.ssh.keys_only = false
    #   n2.vm.provision "shell", inline: $script, env: {'CONSUL_DEMO_VERSION' => CONSUL_DEMO_VERSION}
    consul02.vm.network "private_network", ip: "172.20.20.12"
  end
  
  config.vm.define "consul03" do |consul03|
    consul03.vm.hostname = "consul03"
    # Forward Consul web and api port 8500
    consul03.vm.network "forwarded_port", guest: 8500, host: 8513
      # n3.ssh.username = "root"
      # n3.ssh.password = "P@ssw0rd"
      # n3.ssh.keys_only = false
    #   n3.vm.provision "shell", inline: $script, env: {'CONSUL_DEMO_VERSION' => CONSUL_DEMO_VERSION}
    consul03.vm.network "private_network", ip: "172.20.20.13"
  end

  config.vm.define "vault01" do |vault01|
    vault01.vm.hostname = "vault01"
    # Forward Vault web and api port 8200
    vault01.vm.network "forwarded_port", guest: 8200, host: 8211
    # n6.ssh.username = "root"
    # n6.ssh.password = "P@ssw0rd"
    # n6.ssh.keys_only = false
    # n6.vm.provision "shell", inline: $script, env: {'CONSUL_DEMO_VERSION' => CONSUL_DEMO_VERSION}
    vault01.vm.network "private_network", ip: "172.20.20.16"
  end

  config.vm.define "vault02" do |vault02|
    vault02.vm.hostname = "vault02"
    # Forward Vault web and api port 8200
    vault02.vm.network "forwarded_port", guest: 8200, host: 8212
    # n7.ssh.username = "root"
    # n7.ssh.password = "P@ssw0rd"
    # n7.ssh.keys_only = false
    # n7.vm.provision "shell", inline: $script, env: {'CONSUL_DEMO_VERSION' => CONSUL_DEMO_VERSION}
    vault02.vm.network "private_network", ip: "172.20.20.17"
  end
end