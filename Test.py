#!/usr/bin/python3
from classes.node import node
import json
import os
import time
import copy
import re
#
# consulBinary = "/home/imran/VagrantProjects/Infra/automation/binaries/consul"
# vaultBinary = "/home/imran/VagrantProjects/Infra/automation/binaries/vault"
#
tlsCerts = os.getcwd() + "/tlsCerts/"
# config = None
# try:
#  with open("mnodes.config.json") as f:
#     config = json.loads(f.read())
# except:
#  print("Configuration file error")
# copy_config=copy.deepcopy(config)
# for datacenter in copy_config:
#     print (datacenter['consul_nodes'][4]['ip_address'],"\n",datacenter['domain'])

TLS_Config_File = """
cat << EOM | sudo tee /etc/consul.d/tls_config_file.json
{ 
"verify_incoming": true, 
"verify_outgoing": true, 
"verify_server_hostname": true, 
"ca_file": "/etc/consul.d/consul-agent-ca.pem", 
"cert_file": "/etc/consul.d/@@@TLS-CERT@@@", 
"key_file": "/etc/consul.d/@@@TLS-KEY@@@", 
"ports": { "http": 8500, "https": 8501 } 
}
EOM
"""


config = None
try:
 with open("nodes.config.json") as f:
    config = json.loads(f.read())

except:
 print("Configuration file is missing")


for datacenter in config:
    nodes = datacenter['nodes']
    for n in nodes:
        newNode = None
        if n['ssh_password']:
            newNode = node(n['ip_address'], n['ssh_port'],
                           n['ssh_username'], password=n['ssh_password'])
        elif n['ssh_keyfile']:
            newNode = node(n['ip_address'], n['ssh_port'],
                           n['ssh_username'], keyfile=os.getcwd() + "/" + n['ssh_keyfile'])
        print("Testing Connection Node: %s" % n['hostname'])
        if newNode:
            if newNode.Connect():
                n['node_client'] = newNode

    for n in nodes:
        node = n['node_client']
        'node type: node'
        if not os.path.exists(tlsCerts):
            print(tlsCerts)
            print("Cannot find tls directory")
        # print(n['hostname'])
        # print(tlsCerts)
        # node.GetFile("consul-agent-ca-key.pem", tlsCerts + "consul-agent-ca-key.pem")
        # break

    #
    # num1 = 0
    # num2 = 0
    #
    # tls_created = None
    # totalConsulServers=3
    # totalVaultServers=2
    # primary_dc_name="dc1"
    #
    # print("Configuring Consul Built-in TLS...")
    # for n in nodes:
    #     node = n['node_client']
    #     tls_config_command = str(TLS_Config_File)
    #     n['copied'] = None
    #     if n['Server'] == 'consul':
    #         if tls_created is not True:
    #             for num in range(totalConsulServers):
    #                 if num == 0:
    #                     node.ExecCommand("consul tls ca create")
    #                     node.GetFile("consul-agent-ca.pem", tlsCerts + "/consul-agent-ca.pem")
    #                     node.ExecCommand("consul tls cert create -server")
    #                     node.ExecCommand("sudo cp *.pem /etc/consul.d/", True)
    #                     n['copied'] = True
    #                 else:
    #                     node.ExecCommand("consul tls cert create -server")
    #                     tls_cert = primary_dc_name + "-server-consul-" + str(num) + ".pem"
    #                     tls_key = primary_dc_name + "-server-consul-" + str(num) + "-key.pem"
    #                     node.GetFile(tls_cert, tlsCerts + tls_cert)
    #                     node.GetFile(tls_key, tlsCerts + tls_key)
    #
    #             for num in range(totalVaultServers):
    #                 node.ExecCommand("consul tls cert create -client")
    #                 tls_cert = primary_dc_name + "-client-consul-" + str(num) + ".pem"
    #                 tls_key = primary_dc_name + "-client-consul-" + str(num) + "-key.pem"
    #
    #                 node.GetFile(tls_cert, tlsCerts + tls_cert)
    #                 node.GetFile(tls_key, tlsCerts + tls_key)
    #             print("Succesfully Created TLS Certs on node:%s " % n['hostname'])
    #             tls_created = True
    #
    #         tls_cert = primary_dc_name + "-server-consul-" + str(num1) + ".pem"
    #         tls_key = primary_dc_name + "-server-consul-" + str(num1) + "-key.pem"
    #         print(n['hostname'], " --> ", tls_cert, tls_key)
    #         tls_config_command = tls_config_command.replace("@@@TLS-CERT@@@", "%s" % tls_cert)
    #         tls_config_command = tls_config_command.replace("@@@TLS-KEY@@@", "%s" % tls_key)
    #         n['tls_config_command'] = tls_config_command
    #         print(tls_config_command)
    #         # print(n['hostname'], tls_cert, tls_key)
    #         node.ExecCommand(n['tls_config_command'], True)
    #         if n['copied'] is True:
    #             node.ExecCommand("sudo systemctl restart consul.service", True)
    #             num1 += 1
    #             continue
    #         else:
    #             node.SendFile(tlsCerts + "consul-agent-ca.pem", "consul-agent-ca.pem")
    #             node.SendFile(tlsCerts + tls_cert, tls_cert)
    #             node.SendFile(tlsCerts + tls_key, tls_key)
    #             n['copied'] = True
    #             num1 += 1
    #     if n['Server'] == 'vault':
    #         tls_cert = primary_dc_name + "-client-consul-" + str(num2) + ".pem"
    #         tls_key = primary_dc_name + "-client-consul-" + str(num2) + "-key.pem"
    #         print(n['hostname'], " --> ", tls_cert, tls_key)
    #
    #         tls_config_command = tls_config_command.replace("@@@TLS-CERT@@@", "%s" % tls_cert)
    #         tls_config_command = tls_config_command.replace("@@@TLS-KEY@@@", "%s" % tls_key)
    #         n['tls_config_command'] = tls_config_command
    #         print(n['tls_config_command'])
    #         node.ExecCommand(n['tls_config_command'], True)
    #         node.SendFile(tlsCerts + "consul-agent-ca.pem", "consul-agent-ca.pem")
    #         node.SendFile(tlsCerts + tls_cert, tls_cert)
    #         node.SendFile(tlsCerts + tls_key, tls_key)
    #         num2 += 1
    #     print("Succesfully Coppied TLS Certs to node:%s " % n['hostname'])
    #     node.ExecCommand("sudo mv *.pem /etc/consul.d/", True)
    #     node.ExecCommand("sudo systemctl restart consul.service", True)

    for n in nodes:

        node = n['node_client']
        # node.ExecCommand("sudo rm -rf /etc/consul.d/dc1*.pem", True)
        #
        # if n['Server'] == 'consul':
        #     node.SendFile(tlsCerts + "dc1-server-consul-1.pem", "dc1-server-consul-1.pem")
        #     node.SendFile(tlsCerts + "dc1-server-consul-1-key.pem", "dc1-server-consul-1-key.pem")
        #
        # el
        #     node.SendFile(tlsCerts + "dc1-client-consul-1.pem", "dc1-client-consul-1.pem")
        #     node.SendFile(tlsCerts + "dc1-client-consul-1-key.pem", "dc1-client-consul-1-key.pem")
        #
        # node.ExecCommand("sudo mv *.pem /etc/consul.d/", True)
        node.ExecCommand("sudo sed -i 's/ -1/8500/g' /etc/consul.d/tls_config_file.json", True)
        node.ExecCommand("sudo systemctl restart consul", True)
        print(n['hostname'], " : restarted")

    #     print("Testing Connection Node: %s" % n['hostname'])
    #     if newNode:
    #         if newNode.Connect():
    #             n['node_client'] = newNode
    #             print('Stopping Consul Service on node: %s' % n['hostname'])
    #             newNode.ExecCommand("sudo service consul stop", True)
    #             # print(n['node_client'])
    #             # print(newNode.ExecCommand("apt update", True))
    #             # exit(0)
    # # Copy Consul Binary for each node

# with open("Vault.Status", 'r') as the_file:
#     status_str=the_file.read()
#     if re.search("active", status_str):
#         print("Found")
# num = 0
# total = 3
# for num in range(total):
#     print(num)