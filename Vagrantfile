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
      # consul01.ssh.username = "root"
      # consul01.ssh.password = "P@ssw0rd"
      # consul01.ssh.keys_only = false
    #   consul01.vm.provision "shell", inline: $script, env: {'CONSUL_DEMO_VERSION' => CONSUL_DEMO_VERSION}
    consul01.vm.network "private_network", ip: "172.20.20.11"
  end

  config.vm.define "consul02" do |consul02|
    consul02.vm.hostname = "consul02"
    consul02.vm.network "forwarded_port", guest: 8500, host: 8512
    consul02.vm.network "private_network", ip: "172.20.20.12"
  end
  
  config.vm.define "consul03" do |consul03|
    consul03.vm.hostname = "consul03"
    consul03.vm.network "forwarded_port", guest: 8500, host: 8513
    consul03.vm.network "private_network", ip: "172.20.20.13"
  end

  config.vm.define "vault01" do |vault01|
    vault01.vm.hostname = "vault01"
    vault01.vm.network "forwarded_port", guest: 8200, host: 8211
    vault01.vm.network "private_network", ip: "172.20.20.16"
  end

  config.vm.define "vault02" do |vault02|
    vault02.vm.hostname = "vault02"
    vault02.vm.network "forwarded_port", guest: 8200, host: 8212
    vault02.vm.network "private_network", ip: "172.20.20.17"
  end

  config.vm.define "nginx01" do |nginx01|
    nginx01.vm.hostname = "nginx01"
    nginx01.vm.network "forwarded_port", guest: 80, host: 8081
    nginx01.vm.network "private_network", ip: "172.20.20.19"
  end

  config.vm.define "nginx02" do |nginx02|
    nginx02.vm.hostname = "nginx02"
    nginx02.vm.network "forwarded_port", guest: 80, host: 8082
    nginx02.vm.network "private_network", ip: "172.20.20.20"
  end

  config.vm.define "ssh01" do |ssh01|
    ssh01.vm.hostname = "ssh01"
    ssh01.vm.network "private_network", ip: "172.20.20.22"
  end
end
