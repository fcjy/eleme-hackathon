# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|

  # uncomment the lang you use
  #config.vm.box = "http://hackathon-cdn.ele.me/hackathon-py-0.1.0.vbox"
  #config.vm.box = "http://hackathon-cdn.ele.me/hackathon-java-v0.1.0.vbox"
  config.vm.box = "http://hackathon-cdn.ele.me/hackathon-go-v0.1.0.vbox"

  config.vm.define "vm1" do |vm1| 
    vm1.vm.network "private_network", ip: "192.168.50.1"
    vm1.vm.network :forwarded_port, guest: 6379, host: 6379
    vm1.vm.network :forwarded_port, guest: 3306, host: 3306
    vm1.vm.network :forwarded_port, guest: 8080, host: 8080
  
    config.vm.provider "virtualbox" do |vb|
      vb.customize ["modifyvm", :id, "--memory", "2048"]
      vb.customize ["modifyvm", :id, "--cpus", "4"]
    end  
  end

  config.vm.define "vm2" do |vm2|
    vm2.vm.network "private_network", ip: "192.168.50.2"

    config.vm.provider "virtualbox" do |vb|
      vb.customize ["modifyvm", :id, "--memory", "2048"]
      vb.customize ["modifyvm", :id, "--cpus", "2"]
    end
  end

  # config.vm.box_check_update = false

  config.vm.provision "shell",
    inline: "initctl emit vagrant-mounted",
    run: "always"

end
