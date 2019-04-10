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
# tlsCerts = os.getcwd() + "/tlsCerts/"
# config = None
# try:
#  with open("mnodes.config.json") as f:
#     config = json.loads(f.read())
# except:
#  print("Configuration file error")
# copy_config=copy.deepcopy(config)
# for datacenter in copy_config:
#     print (datacenter['consul_nodes'][4]['ip_address'],"\n",datacenter['domain'])

# TLS_Config_File = """
# cat << EOM | sudo tee /etc/consul.d/tls_config_file.json
# {
# "verify_incoming": true,
# "verify_outgoing": true,
# "verify_server_hostname": true,
# "ca_file": "/etc/consul.d/consul-agent-ca.pem",
# "cert_file": "/etc/consul.d/@@@TLS-CERT@@@",
# "key_file": "/etc/consul.d/@@@TLS-KEY@@@",
# "ports": { "http": 8500, "https": 8501 }
# }
# EOM
# """
#
#
Consul_Config = """
cat << EOM | sudo tee /etc/consul.d/consul.hcl
datacenter = "dc1"
data_dir = "/opt/consul"
encrypt = "c5x86t3e68ibksMc306Rxg=="
ui = true
server = true
bootstrap_expect = 3
performance {  raft_multiplier = 1 }

recursors=["192.168.192.1"]
primary_datacenter="dc1"
acl = {
  enabled = true
  default_policy = "deny"
  down_policy = "extend-cache"
  tokens = {
      agent = "54e31ea7-3fb3-6d69-2f59-c98f069df747"
  }
}
addresses = {
   http = "0.0.0.0"
}
log_level="INFO"
enable_syslog = true
bind_addr = "{{ GetInterfaceIP \\"enp0s8\\" }}"
ports = { dns = 53 }
EOM
"""


PKI_Policy_File = """
cat << EOM | sudo tee pki_policy_file.hcl
path "sys/mounts/*" {
  capabilities = [ "create", "read", "update", "delete", "list" ]
}
path "sys/mounts" {
  capabilities = [ "read", "list" ]
}
path "pki*" {
  capabilities = [ "create", "read", "update", "delete", "list", "sudo" ]
}
EOM
"""

TLS_Config_File = """
cat << EOM | sudo tee /etc/consul.d/tls_config_file.json
{ 
"verify_incoming": true, 
"verify_outgoing": true, 
"verify_server_hostname": true, 
 "ca_file" : "http://vault.service.consul:8200/v1/pki/ca/pem",
"ports": { "http": 8500, "https": 8501 } 
}
EOM
"""
Connect_Config_File = """
cat << EOM | sudo tee /etc/consul.d/connect_config_file.hcl

connect {
    enabled = true
    ca_provider = "vault"
    ca_config {
        address = "http://vault.service.consul:8200"
        token = "@@@TOKEN@@@"
        root_pki_path = "pki"
        intermediate_pki_path = "pki_int/"
    }
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
    # compnodes = datacenter['comp_nodes']
    for n in nodes:
    # for n in compnodes:
        newNode = None
        if n['ssh_password']:
            newNode = node(n['ip_address'], n['ssh_port'],
                           n['ssh_username'], password=n['ssh_password'])
        elif n['ssh_keyfile']:
            newNode = node(n['ip_address'], n['ssh_port'],
                           n['ssh_username'], keyfile=os.getcwd() + "/" + n['ssh_keyfile'])
        print("Testing Connection to Node: %s  -> " % n['hostname'], end='')
        if newNode:
            if newNode.Connect():
                n['node_client'] = newNode
            if n['Server'] == "ssh":
                ssh_server_ip = n['ip_address']
    # regexp = r'Initial Root Token: ([^\n]+)'
    # with open('Vault.Secrets', 'r') as the_file:
    #     for line in the_file:
    #         if "Root Token" in line:
    #             rtoken = re.findall(regexp, line)

    regexp1 = r'Unseal Key [\d]+: ([^\n]+)'
    regexp2 = r'Initial Root Token: ([^\n]+)'
    keys = []
    with open('Vault.Secrets', 'r') as the_file:
        for line in the_file:
            if "Unseal" in line:
                keys.append(re.findall(regexp1, line))
            if "Root Token" in line:
                rtoken = re.findall(regexp2, line)

    for n in nodes:
        node = n['node_client']
        if n['Server'] == 'consul':

            node.ExecCommand("sudo sed -i 's/http:/https:/' /etc/consul.d/connect_config_file.hcl")
            # node.ExecCommand("sudo sed -i 's/8200/8201/' /etc/consul.d/connect_config_file.hcl")
            # node.ExecCommand("sudo systemctl restart consul", True)
        # print("Installing JQ on Node -> %s" % n['hostname'])
        # node.ExecCommand("sudo sed -i '/vivid/d' /etc/apt/sources.list", True)
        # node.ExecCommand("sudo sed -i -e \"\$a deb http://old-releases.ubuntu.com/ubuntu vivid main universe\" "
        #                  "/etc/apt/sources.list", True)
        # node.ExecCommand("sudo apt update", True)
        # node.ExecCommand("sudo apt install -y jq", True)

        if n['Server'] == 'vault':

            node.ExecCommand("sudo systemctl restart vault", True)

            print("Unsealing Vault node: %s..." % n['hostname'])
            time.sleep(5)
            node.ExecCommand(
                "vault operator unseal -ca-cert=/etc/consul.d/consul-agent-ca.pem %s" % keys[1][0], True)
            node.ExecCommand(
                "vault operator unseal -ca-cert=/etc/consul.d/consul-agent-ca.pem %s" % keys[2][0], True)
            node.ExecCommand(
                "vault operator unseal -ca-cert=/etc/consul.d/consul-agent-ca.pem %s" % keys[3][0], True)
        node.ExecCommand("sudo systemctl restart consul", True)

    # for n in nodes:
    #     node = n['node_client']
    #     print("Restarting Consul")
    #     time.sleep(2)
    #     node.ExecCommand("sudo systemctl restart consul", True)
    # regexp1 = r'out\': \[\'([^\\]+)'
    # for n in nodes:
    #     node = n['node_client']
    #     'node type: node'
    #     pki_engine_enabled = None
    #     if n['Server'] == "vault":
    #         if pki_engine_enabled is not True:
    #             print("Checking Vault Status on %s -> " % n['hostname'], end='')
    #             file_name = n['hostname'] + ".status"
    #             time.sleep(2)
    #             node.ExecCommand("vault status -address=\"http://127.0.0.1:8200\" | sudo tee %s" % file_name)
    #             node.GetFile(file_name, os.getcwd() + "/%s" % file_name)
    #             with open(file_name, 'r') as the_file:
    #                 status_str = the_file.read()
    #                 if re.search("active", status_str):
    #                     print("Active \n")
    #
    #                     print("Creating PKI Secret Engine policy and token...")
    #                     node.ExecCommand("vault login -address=\"http://127.0.0.1:8200\" %s" % rtoken[0])
    #                     node.ExecCommand("sudo %s" % str(PKI_Policy_File), True)
    #                     node.ExecCommand("vault policy write -address=\"http://127.0.0.1:8200\" pki_policy pki_policy_file.hcl", True)
    #                     # pki_token = re.findall(regexp1, str(node.ExecCommand("vault token create -address=\"http://127.0.0.1:8200\" -policy=pki_policy |awk 'FNR == 3 {print $2}'")))
    #                     pki_token_a = node.ExecCommand(
    #                         "vault token create -address=\"http://127.0.0.1:8200\" -policy=pki_policy |awk 'FNR == 3 {print $2}'")
    #                     print("pki raw -> ", pki_token_a, "\n\n\n")
    #                     pki_token = re.findall(regexp1, str(pki_token_a))
    #                     print("pki list item-> ", pki_token, "\n\n\n")
    #                     print("pki token -> ", pki_token[0], "\n\n\n")
    #                     pki_engine_enabled = True
    #                     break
    #                 else:
    #                     print("Standby \n")

    # for n in nodes:
    #     node = n['node_client']
    #     # node.ExecCommand("sudo chown consul: -R /etc/consul.d")
    #     #
    #     # if n['Server'] == 'consul':
    #     #     node.ExecCommand("sudo rm -rf /etc/consul.d/consul.hcl", True)
    #     #     node.ExecCommand("sudo %s" % str(Consul_Config), True)
    #     node.ExecCommand("sudo sed -i 's/8500/-1/' /etc/consul.d/tls_config_file.json", True)
    #     # node.ExecCommand("sudo %s" % str(TLS_Config_File), True)
    #     # if n['Server'] == 'consul':
    #
    #     # connect_config = str(Connect_Config_File)
    #     # # connect_config = connect_config.replace("@@@TOKEN@@@", rtoken[0])
    #     # connect_config = connect_config.replace("@@@TOKEN@@@", "s.j2ToesuHxI9WmeMQVcCoe4qp")
    #     # node.ExecCommand("sudo %s" % connect_config, True)
    #     # node.ExecCommand("sudo export VAULT_TOKEN=s.j2ToesuHxI9WmeMQVcCoe4qp", True)
    # #
    # #     # if n['Server'] != 'nginx':
    # #
    # #
    # #     # node.ExecCommand("sudo sed -i '/^\"key.*/ s/cert.crt/key.pem/' /etc/consul.d/tls_config_file.json", True)
    # #     # node.ExecCommand("sudo sed -i 's/.crt/.pem/g' /etc/consul.d/tls_config_file.json", True)
    #     print("Restarting consul on Node: %s  -> " % n['hostname'])
    #     node.ExecCommand("sudo systemctl restart consul.service", True)

#     # regexp1 = r'Unseal Key [\d]+: ([^\n]+)'
#     regexp2 = r'Initial Root Token: ([^\n]+)'
#     # i = 0
#     # keys = []
#     with open('Vault.Secrets', 'r') as the_file:
#         for line in the_file:
#             # if "Unseal" in line:
#             #     keys.append(re.findall(regexp1, line))
#             #     # m = keys[i]
#             #     # print(m[0].strip())
#             #     i += 1
#             if "Root Token" in line:
#                 rtoken = re.findall(regexp2, line)
#
#     for n in nodes:
#         node = n['node_client']
#         'node type: node'
#         if n['Server'] == "vault":
#             file_name = n['hostname'] + ".status"
#             print("Enabling SSH Secret Engine on Vault ")
#             node.ExecCommand("vault status -address=\"http://127.0.0.1:8200\" | sudo tee %s" % file_name)
#             node.GetFile(file_name, os.getcwd() + "/%s" % file_name)
#             with open(file_name, 'r') as the_file:
#                 status_str = the_file.read()
#                 if re.search("active", status_str):
#                     active_vault_ip = n['ip_address']
#                     node.ExecCommand("vault login %s" % rtoken[0])
#                     node.ExecCommand("vault secrets enable -address=\"http://127.0.0.1:8200\" ssh")
#                     print("Creating an OTP Key Role...")
#                     node.ExecCommand("vault write -address=\"http://127.0.0.1:8200\" ssh/roles/otp_key_role key_type=otp default_user=ubuntu cidr_list=0.0.0.0/0 address=127.0.0.1:8500")
#                     ssh_keys = node.ExecCommand(
#                         "vault write -address=\"http://127.0.0.1:8200\" ssh/creds/otp_key_role ip=%s | awk 'FNR == 7 {print $0}'" % ssh_server_ip)
#                     print(''.join(ssh_keys['out']))
#                     break
#
#     for n in compnodes:
#         # print(n)
#         node = n['node_client']
#
#         node.ExecCommand("sudo apt update")
#         node.ExecCommand("sudo apt install -y unzip")
#         print("Installed unzip on node: %s" % n['hostname'])
#         node.ExecCommand(
#             "sudo wget https://releases.hashicorp.com/vault-ssh-helper/0.1.4/vault-ssh-helper_0.1.4_linux_amd64.zip",
#             True)
#         print("Unzipping Helper File...")
#         node.ExecCommand("sudo unzip -qf vault-ssh-helper_0.1.4_linux_amd64.zip -d /usr/local/bin")
#         print("Unzipped done!")
#         node.ExecCommand(" sudo chmod 0755 /usr/local/bin/vault-ssh-helper")
#         node.ExecCommand("sudo chown root:root /usr/local/bin/vault-ssh-helper")
#         print("Copied vault-ssh-helper")
#         node.ExecCommand("sudo mkdir /etc/vault-ssh-helper.d")
#         node.SendFile(os.getcwd() + "/tlsCerts/consul-agent-ca.pem", "vault.crt")
#         print("Succesfully Coppied CA Cert to node:%s " % n['hostname'])
#         node.ExecCommand("sudo mv vault.crt /etc/vault-ssh-helper.d/", True)
#         vault_ssh_config = str(Vault_Helper_SSH_Config_File)
#         vault_ssh_config = vault_ssh_config.replace("@@@VAULT-IP@@@", active_vault_ip)
#         node.ExecCommand("sudo %s" % vault_ssh_config, True)
#         print("Created Vault Helper SSH config file...")
#         node.ExecCommand("sudo sed -i '/common-auth/s/^/#/g' /etc/pam.d/sshd")
#         node.ExecCommand(
#             "sudo sed -i '/common-auth/a auth optional pam_unix.so not_set_pass use_first_pass nodelay' /etc/pam.d/sshd")
#         node.ExecCommand(
#             "sudo sed -i '/common-auth/a auth requisite pam_exec.so quiet expose_authtok log=/tmp/vaultssh.log /usr/local/bin/vault-ssh-helper -dev -config=/etc/vault-ssh-helper.d/config.hcl' /etc/pam.d/sshd")
#         node.ExecCommand(
#             "sudo sed -i 's/^#\?ChallengeResponse.*/ChallengeResponseAuthentication yes/g' /etc/ssh/sshd_config")
#         node.ExecCommand(
#             "sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/g' /etc/ssh/sshd_config")
#         node.ExecCommand(
#             "sudo sed -i 's/^#\?UsePAM.*/UsePAM yes/g' /etc/ssh/sshd_config")
#         print("Restarting SSH service...")
#         node.ExecCommand("sudo systemctl restart sshd")


        # node = n['node_client']
        # 'node type: node'
        # if not os.path.exists(tlsCerts):
        #     print(tlsCerts)
        #     print("Cannot find tls directory")
        # # print(n['hostname'])
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

    # for n in nodes:
    #
    #     node = n['node_client']
    #     # node.ExecCommand("sudo rm -rf /etc/consul.d/dc1*.pem", True)
    #     #
    #     # if n['Server'] == 'consul':
    #     #     node.SendFile(tlsCerts + "dc1-server-consul-1.pem", "dc1-server-consul-1.pem")
    #     #     node.SendFile(tlsCerts + "dc1-server-consul-1-key.pem", "dc1-server-consul-1-key.pem")
    #     #
    #     # el
    #     #     node.SendFile(tlsCerts + "dc1-client-consul-1.pem", "dc1-client-consul-1.pem")
    #     #     node.SendFile(tlsCerts + "dc1-client-consul-1-key.pem", "dc1-client-consul-1-key.pem")
    #     #
    #     # node.ExecCommand("sudo mv *.pem /etc/consul.d/", True)
    #     node.ExecCommand("sudo sed -i 's/ -1/8500/g' /etc/consul.d/tls_config_file.json", True)
    #     node.ExecCommand("sudo systemctl restart consul", True)
    #     print(n['hostname'], " : restarted")

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

# test_str = "This is test"
# print('-->', end='', flush=True)
# print(test_str)
