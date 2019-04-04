#!/usr/bin/python3
from classes.node import node
import json
import os
import time
import re

config = None
try:
 with open("nodes.config_all.json") as f:
    config = json.loads(f.read())

except:
 print("Configuration file is missing")

Vault_Helper_SSH_Config_File = """
cat << EOM |sudo tee /etc/vault-ssh-helper.d/config.hcl
vault_addr = "http://@@@VAULT-IP@@@:8200"
ssh_mount_point = "ssh"
ca_cert = "/etc/vault-ssh-helper.d/vault.crt"
tls_skip_verify = false
allowed_roles = "*"
EOM
"""

for datacenter in config:
    nodes = datacenter['nodes']
    compnodes = datacenter['comp_nodes']
    for n in (nodes + compnodes):
        newNode = None
        if n['ssh_password']:
            newNode = node(n['ip_address'], n['ssh_port'],
                           n['ssh_username'], password=n['ssh_password'])
        elif n['ssh_keyfile']:
            newNode = node(n['ip_address'], n['ssh_port'],
                           n['ssh_username'], keyfile=os.getcwd() + "/" + n['ssh_keyfile'])
        print("Testing Connection to Node: %s -> " % n['hostname'], end='')
        if newNode:
            if newNode.Connect():
                n['node_client'] = newNode
            if n['Server'] == "ssh":
                ssh_server_ip = n['ip_address']

    regexp = r'Initial Root Token: ([^\n]+)'
    with open('Vault.Secrets', 'r') as the_file:
        for line in the_file:
            if "Root Token" in line:
                rtoken = re.findall(regexp, line)
    print("\n => Established connection to all the nodes!!! <=\n")
    time.sleep(2)
    for n in nodes:
        node = n['node_client']
        'node type: node'
        ssh_engine_enable = None
        if n['Server'] == "vault":
            if ssh_engine_enable is not True:
                print("Checking Vault Status on %s -> " % n['hostname'], end='')
                file_name = n['hostname'] + ".status"
                time.sleep(2)
                node.ExecCommand("vault status -address=\"http://127.0.0.1:8200\" | sudo tee %s" % file_name)
                node.GetFile(file_name, os.getcwd() + "/%s" % file_name)
                with open(file_name, 'r') as the_file:
                    status_str = the_file.read()
                    if re.search("active", status_str):
                        print("Active \n")
                        print("Enabling SSH Secret Engine on %s...\n" % n['hostname'])
                        active_vault_ip = n['ip_address']
                        node.ExecCommand("vault login -address=\"http://127.0.0.1:8200\" %s" % rtoken[0])
                        node.ExecCommand("vault secrets enable -address=\"http://127.0.0.1:8200\" ssh")
                        print("Creating an OTP Key Role...\n")
                        time.sleep(2)
                        node.ExecCommand(
                            "vault write -address=\"http://127.0.0.1:8200\" ssh/roles/otp_key_role key_type=otp default_user=ubuntu cidr_list=0.0.0.0/0 address=127.0.0.1:8500")
                        print("Generating first OTP...\n")
                        time.sleep(2)
                        ssh_keys = node.ExecCommand(
                            "vault write -address=\"http://127.0.0.1:8200\" ssh/creds/otp_key_role ip=%s | awk 'FNR == 7 {print $2}'" % ssh_server_ip)
                        print("Please execute -> \"ssh ubuntu@%s\" and supply the OTP key -> %s" % (
                        ssh_server_ip, ''.join(ssh_keys['out'])))
                        ssh_engine_enable = True
                        break
                    else:
                        print("Standby \n")

    for n in compnodes:
        node = n['node_client']
        node.ExecCommand("sudo apt update")
        node.ExecCommand("sudo apt install -y unzip")
        node.ExecCommand(
            "sudo wget https://releases.hashicorp.com/vault-ssh-helper/0.1.4/vault-ssh-helper_0.1.4_linux_amd64.zip",
            True)
        node.ExecCommand("sudo unzip -qf vault-ssh-helper_0.1.4_linux_amd64.zip -d /usr/local/bin")
        node.ExecCommand(" sudo chmod 0755 /usr/local/bin/vault-ssh-helper")
        node.ExecCommand("sudo chown root:root /usr/local/bin/vault-ssh-helper")
        node.ExecCommand("sudo mkdir /etc/vault-ssh-helper.d")
        node.SendFile(os.getcwd() + "/tlsCerts/consul-agent-ca.pem", "vault.crt")
        node.ExecCommand("sudo mv vault.crt /etc/vault-ssh-helper.d/", True)
        vault_ssh_config = str(Vault_Helper_SSH_Config_File)
        vault_ssh_config = vault_ssh_config.replace("@@@VAULT-IP@@@", active_vault_ip)
        node.ExecCommand("sudo %s" % vault_ssh_config, True)
        node.ExecCommand(
            "sudo sed -i '/^@include common-auth/a auth optional pam_unix.so not_set_pass use_first_pass nodelay' /etc/pam.d/sshd")
        node.ExecCommand(
            "sudo sed -i '/^@include common-auth/a auth requisite pam_exec.so quiet expose_authtok log=/tmp/vaultssh.log /usr/local/bin/vault-ssh-helper -dev -config=/etc/vault-ssh-helper.d/config.hcl' /etc/pam.d/sshd")
        node.ExecCommand("sudo sed -i '/^@include common-auth/s/^/#/g' /etc/pam.d/sshd")
        node.ExecCommand(
            "sudo sed -i 's/^#\?ChallengeResponse.*/ChallengeResponseAuthentication yes/g' /etc/ssh/sshd_config")
        node.ExecCommand(
            "sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/g' /etc/ssh/sshd_config")
        node.ExecCommand(
            "sudo sed -i 's/^#\?UsePAM.*/UsePAM yes/g' /etc/ssh/sshd_config")
        node.ExecCommand("sudo systemctl restart sshd")
