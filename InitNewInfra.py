#!/usr/bin/python3
from classes.node import node
import json
import os
import time
import copy
import re

consulBinary = os.getcwd() + "/binaries/consul"
vaultBinary = os.getcwd() + "/binaries/vault"
tlsCerts = os.getcwd() + "/tlsCerts/"
pkiCerts = os.getcwd() + "/pkiCerts/"

Connect_Config_File = """
cat << EOM | sudo tee /etc/consul.d/connect_config_file.hcl
connect {
    enabled = true
    ca_provider = "vault"
    ca_config {
        address = "http://vault.service.consul:8200"
        token = "@@@VAULT-TOKEN@@@"
        root_pki_path = "pki"
        intermediate_pki_path = "pki_int"
    }
  }
EOM
"""

Connect_Consul_Config_File = """
cat << EOM | sudo tee /etc/consul.d/connect_config_file.hcl
connect {
enabled = true
}
EOM
"""

Create_Consul_Service_Command = """
cat << EOM | sudo tee /etc/systemd/system/consul.service
[Unit]
Description="HashiCorp Consul - A service mesh solution"
Documentation=https://www.consul.io/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/consul.d/consul.hcl

[Service]
User=consul
Group=consul
ExecStartPre=/sbin/setcap 'cap_net_bind_service=+ep' /usr/local/bin/consul
PermissionsStartOnly=true
ExecStart=/usr/local/bin/consul agent -config-dir=/etc/consul.d/
ExecReload=/bin/kill --signal HUP $MAINPID
KillMode=process
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""

Create_Consul_Config_File = """
cat << EOM | sudo tee /etc/consul.d/consul.hcl
datacenter = "@@@DATACENTER_NAME@@@"
data_dir = "/opt/consul"
encrypt = "@@@GOSIP_ENC_KEY@@@"
ui = @@@CONSUL_UI@@@
server = @@@IS_SERVER@@@
@@@BOOTSTRAP@@@
@@@PERFORMANCE@@@
@@@RETRY_JOIN@@@
@@@RECURSORS@@@
@@@PRIMARY_DATACENTER_NAME@@@
acl = {
  #@@@ACL_ENABLE@@@
  default_policy = "deny"
  down_policy = "extend-cache"
  tokens = {
      agent = "@@@AGENT_TOKEN@@@"
  }
}
addresses = {
   http = "0.0.0.0"
}
@@@LOG_LEVEL@@@
enable_syslog = true
bind_addr = "{{ GetInterfaceIP \\"@@@INTERFACE@@@\\" }}"
ports = { dns = 53 }
EOM
"""

Create_Vault_Service_Command = """
cat << EOM | sudo tee /etc/systemd/system/vault.service
[Unit]
Description="HashiCorp Vault secret management tool"
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/vault.d/vault.hcl

[Service]
User=vault
Group=vault
ExecStartPre=/sbin/setcap 'cap_ipc_lock=+ep' /usr/local/bin/vault
PermissionsStartOnly=true
ExecStart=/usr/local/bin/vault server -config=/etc/vault.d/ -log-level=info
ExecReload=/bin/kill --signal HUP $MAINPID
KillMode=process
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""



Create_Vault_Config_File = """
cat << EOM | sudo tee /etc/vault.d/vault.hcl
ui = true
listener "tcp" {
  address          = "0.0.0.0:8200"
  cluster_address  = "@@@VAULT_SERVER_IP@@@:8201"
  tls_disable      = "@@@TLS@@@"
}

storage "consul" {
  address = "127.0.0.1:8500"
  path    = "vault/"
  token = "@@@VAULT_TOKEN@@@"
}

api_addr = "http://@@@VAULT_SERVER_IP@@@:8200"
cluster_addr = "https://@@@VAULT_SERVER_IP@@@:8201"
EOM
"""

Create_Nginx_Index_File = """
cat << EOM | sudo tee /var/www/html/index.html
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
</head>
<body>
<h1>You're at @@@NGINX-HOST@@@ Server!</h1>
</body>
</html>
EOM
"""

Create_Nginx_Service_Command = """
cat << EOM | sudo tee /etc/consul.d/nginx_config_file.json
{
 "service": {
  "id": "nginx",
  "name": "nginx",
  "port": 80,
  "token": "@@@NGINX_TOKEN@@@",
  "checks": [
    {
      "Name": "NGINX Listening",
      "TCP": "@@@NGINX-IP@@@:80",
      "Interval": "10s"
    }],
    "connect": {
    "proxy": {
      "config": {
        "bind_address" : "@@@NGINX-IP@@@"
      }
    }
  }
 }
}
EOM
"""


Agent_Policy_File = """
cat << EOM | sudo tee agent_policy_file.hcl
node_prefix "" {
   policy = "write"
}
service_prefix "" {
   policy = "read"
}
EOM
"""

Anonymous_Policy_File = """
cat << EOM | sudo tee anonymous_policy_file.hcl
node_prefix "" {
   policy = "read"
}
service_prefix "" {
   policy = "read"
}
EOM
"""

Vault_Policy_File = """
cat << EOM | sudo tee vault_policy_file.hcl
key_prefix "vault/" {
    policy = "write"
}
node_prefix "" {
    policy = "write"
}
service "vault" {
    policy = "write"
}
agent_prefix "" {
    policy = "write"
}
session_prefix "" {
    policy = "write"
}
EOM
"""

Nginx_Policy_File = """
cat << EOM | sudo tee nginx_policy_file.hcl
agent "" {
    policy = "read"
}
node_prefix "nginx" {
    policy = "write"
}
service_prefix "nginx" {
    policy = "write"
}
session_prefix "" {
    policy = "write"
}
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
"ca_file": "/etc/consul.d/consul-agent-ca.pem", 
"cert_file": "/etc/consul.d/@@@TLS-CERT@@@", 
"key_file": "/etc/consul.d/@@@TLS-KEY@@@", 
"ports": { "http": -1, "https": 8501 } 
}
EOM
"""


config = None
try:
 with open("nodes.config.json") as f:
    config = json.loads(f.read())
except:
 print("Configuration file is missing")     


UpDateConfigFileWhenFinished = False
for datacenter in config:
    if datacenter['gosip_encryption_key'] == "":
        print("No Consul Gosip Key specified for datacenters %s, generating new one" %
              datacenter['datacenter_name'])
        datacenter['gosip_encryption_key'] = os.popen(
            consulBinary + " keygen").read().strip()
        UpDateConfigFileWhenFinished = True

# make a copy of the original config, we need this later for re-wrting nodes.config.json
# we have to do this now, before we start adding extra shit into original config variable

config_backUp = copy.deepcopy(config)

primaryDataCenterIsSet = False
primary_dc_name = ""
for datacenter in config:
    dc_name = datacenter['datacenter_name']
    print("Datancenter Named: %s will be assumed to be the master datacenter" % dc_name)
    if not primaryDataCenterIsSet:
        primary_dc_name = dc_name
        primaryDataCenterIsSet = True
    dc_domain = datacenter['domain']
    dc_gosip_encryption_key = datacenter['gosip_encryption_key']

    nodes = datacenter['nodes']
    totalConsulServers = 0
    totalVaultServers = 0
    totalNginxServers = 0
    retry_join_string = ""
    for n in nodes:
        if n['Server'] == "consul":
            totalConsulServers += 1
            retry_join_string += '"' + n['ip_address'] + '"' + ", "
        elif n['Server'] == "vault":
            totalVaultServers += 1
        elif n['Server'] == "nginx":
            totalNginxServers += 1

    if totalConsulServers < 3:
        print("Invalid number of consul nodes, minimum 3, recommened 5")
        exit(1)
    elif totalVaultServers < 2:
        print("Invalid number of vault nodes, minimum 2")
        exit(1)

    join_string = ""
    for cn in nodes:
        join_string += cn['ip_address'] + " "

    for n in nodes:
        newNode = None
        if n['ssh_password']:
            newNode = node(n['ip_address'], n['ssh_port'],
                           n['ssh_username'], password=n['ssh_password'])
        elif n['ssh_keyfile']:
            newNode = node(n['ip_address'], n['ssh_port'],
                           n['ssh_username'], keyfile=os.getcwd() + "/" + n['ssh_keyfile'])
        print("Testing Connection to Node: %s --> " % n['hostname'], end='')
        if newNode:
            if newNode.Connect():
                n['node_client'] = newNode
    print("\nSetting up HashiCorp Consul - A service mesh solution...\n")
    time.sleep(1)
    for n in nodes:
        node = n['node_client']
        'node type: node'
        if not os.path.exists(consulBinary):
            print("Cannot find consul binary")

        # we have to create a real config.hcl string now
        # make a copy of the original string
        config_hcl = str(Create_Consul_Config_File)

        config_hcl = config_hcl.replace(
            "@@@DATACENTER_NAME@@@", dc_name)
        config_hcl = config_hcl.replace(
            "@@@GOSIP_ENC_KEY@@@", dc_gosip_encryption_key)
        if n['UI']:
            config_hcl = config_hcl.replace(
                "@@@CONSUL_UI@@@", "true")
        else:
            config_hcl = config_hcl.replace(
                "@@@CONSUL_UI@@@", "false")

        if n['Server'] == "consul":
            config_hcl = config_hcl.replace(
                "@@@IS_SERVER@@@", "true")
            config_hcl = config_hcl.replace(
                "@@@BOOTSTRAP@@@", "bootstrap_expect = %d" % totalConsulServers)
            config_hcl = config_hcl.replace(
                "@@@PERFORMANCE@@@", "performance {  raft_multiplier = 1 }")
            recurosrs_string = ""
            for rc in datacenter['datacenter_default_dns_resolvers']:
                recurosrs_string += '"' + rc + '"' + ", "
            recurosrs_string = recurosrs_string[:-2]
            config_hcl = config_hcl.replace(
                "@@@RECURSORS@@@", "recursors=[%s]" % recurosrs_string)
            config_hcl = config_hcl.replace(
                "@@@RETRY_JOIN@@@", "")
        else:
            config_hcl = config_hcl.replace(
                "@@@IS_SERVER@@@", "false")
            config_hcl = config_hcl.replace(
                "@@@BOOTSTRAP@@@", "")
            config_hcl = config_hcl.replace(
                "@@@PERFORMANCE@@@", "")
            config_hcl = config_hcl.replace(
                "@@@RECURSORS@@@", "")
            config_hcl = config_hcl.replace(
                "@@@RETRY_JOIN@@@", "retry_join=[%s]" % retry_join_string[:-2])

        if n['LogLevel']:
            config_hcl = config_hcl.replace(
                "@@@LOG_LEVEL@@@", "log_level=\"%s\"" % n['LogLevel'])
        else:
            config_hcl = config_hcl.replace(
                "@@@LOG_LEVEL@@@", "")
        config_hcl = config_hcl.replace(
            "@@@PRIMARY_DATACENTER_NAME@@@", "primary_datacenter=\"%s\"" % primary_dc_name)
        config_hcl = config_hcl.replace(
            "@@@INTERFACE@@@", n['ethernet_interface_name'])
        # if n['DNS_PORT_53']:
        #     config_hcl = config_hcl.replace(
        #         "@@@PORTS_CONFIG@@@", "ports = { dns = 53 }")
        # else:
        #     config_hcl = config_hcl.replace(
        #         "@@@PORTS_CONFIG@@@", "")
        # End OF Generating Config.hcl string
        # print(config_hcl)
        n['config_hcl_command'] = config_hcl
        RequiresReboot = False
        node.ExecCommand("sudo apt install -y unzip curl dnsutils uuid", True)
        result = node.ExecCommand("hostname")
        if result['out'][0].strip() != n['hostname']:
            print("Original hostname is: %s, Wanted Hostname: %s, We have to change it" % (
                result['out'][0].strip(), n['hostname']))
            node.ExecCommand("sudo  hostnamectl set-hostname %s" %
                             n['hostname'], True)
            RequiresReboot = True

        node.ExecCommand("sudo rm -rf ~/* ", True)
        print("Stopping consul service (if any) on node \"%s\" and copying CONSUL binary file" % n['hostname'].upper())
        node.SendFile(consulBinary, "consul")
        node.ExecCommand("sudo systemctl stop consul", True)
        node.ExecCommand("sudo rm -rf /opt/consul", True)
        node.ExecCommand("sudo rm -rf /etc/consul.d", True)
        node.ExecCommand("sudo hostnamectl set-hostname", True)
        node.ExecCommand("sudo mkdir --parents /opt/consul", True)
        node.ExecCommand("sudo mkdir /etc/consul.d", True)
        node.ExecCommand(
            "sudo useradd --system --home /etc/consul.d --shell /bin/false consul", True)
        node.ExecCommand("sudo chown --recursive consul:consul /opt/consul", True)
        node.ExecCommand("sudo chmod a+x consul", True)
        node.ExecCommand("sudo mv consul /usr/local/bin", True)
        node.ExecCommand("sudo chmod a+w /etc/consul.d", True)
        node.ExecCommand(
            "sudo chown --recursive consul:consul /etc/consul.d", True)
        node.ExecCommand(
            "sudo consul -autocomplete-install", True)
        node.ExecCommand(
            "sudo complete -C /usr/local/bin/consul consul", True)
        node.ExecCommand(config_hcl, True)
        node.ExecCommand(Create_Consul_Service_Command, True)
        if n['Server'] == "consul":
            print("Disabling SYSTEMD-RESOLVED.SERVICE on Consul Server \"%s\" to free up DNS port 53"
                  % n['hostname'].upper())
            node.ExecCommand("sudo systemctl stop systemd-resolved", True)
            node.ExecCommand("sudo systemctl disable systemd-resolved", True)
            node.ExecCommand("sudo rm -f /etc/resolv.conf", True)
        else:
            print("Updating Domain \"consul\" in resolved.conf file and setting up DNS forwarding on port 53"
                  " for node \"%s\"" % n['hostname'].upper())
            node.ExecCommand("sudo bash -c \"echo DNS=127.0.0.1 >> /etc/systemd/resolved.conf\"")
            node.ExecCommand("sudo bash -c \"echo Domains='~consul' >> /etc/systemd/resolved.conf\"")
            node.ExecCommand("sudo systemctl restart systemd-resolved", True)
            node.ExecCommand("sudo systemctl enable systemd-resolved", True)

        node.ExecCommand("sudo systemctl enable consul", True)
        node.ExecCommand("sudo systemctl daemon-reload", True)
        node.ExecCommand("sudo service consul stop", True)
        if RequiresReboot:
            print("Node %s going to reboot now" % n['hostname'])
    print("")
    for n in nodes:
        node = n['node_client']
        print('Starting Consul Service on node: %s' % n['hostname'])
        node.ExecCommand("sudo service consul start", True)
    print("Sleeping for 5 seconds until cluster is ready and bootstraped...")
    time.sleep(5)
    for n in nodes:
        if n['Server'] == "consul":
            node = n['node_client']
            node.ExecCommand("sudo consul join %s" % join_string)
            break

    print("Enabling ACL on all nodes and restarting the servers...")
    for n in nodes:
        node = n['node_client']
        n['config_hcl_command'] = n['config_hcl_command'].replace("#@@@ACL_ENABLE@@@", "enabled = true")
        node.ExecCommand(n['config_hcl_command'], True)

    for n in nodes:
        node = n['node_client']
        node.ExecCommand("sudo service consul restart", True)
    print("Sleeping for another 5 seconds until ACL is ready...\n")
    time.sleep(5)

    agent_policy_command = str(Agent_Policy_File)
    anonymous_policy_command = str(Anonymous_Policy_File)
    vault_policy_command = str(Vault_Policy_File)
    nginx_policy_command = str(Nginx_Policy_File)
    anonymous_id = "00000000-0000-0000-0000-000000000002"
    master_token = None
    agent_token = None
    regexp = r'out\': \[\'([^\\n\'\]]+)'

    for n in nodes:
        if n['Server'] == "consul":
            node = n['node_client']
            print("Running ACL bootstrap on first server node \"%s\" " % n['hostname'].upper())
            result = node.ExecCommand("sudo consul acl bootstrap |tee Master.Token", True)
            # print("Saved file Master.Token on node: %s " % n['hostname'], "\n")
            with open('Master.token', 'w') as the_file:
                the_file.writelines(result['out'])
                print("Saved Master.Token locally")
            mtoken = re.findall(regexp, str(node.ExecCommand("cat Master.Token | awk 'FNR == 2 {print $2}'")))
            master_token = mtoken[0].strip()
            print("Consul Master Token -> %s \n" % master_token)

            print("Creating ACL tokens for Consul Agent, Vault and NGINX and their associated policies...")
            if master_token is not None:
                node.ExecCommand(agent_policy_command, True)
                node.ExecCommand(
                    "consul acl policy create -name 'agent_policy' -rules @agent_policy_file.hcl -token %s"
                    % master_token)
                atoken = re.findall(regexp, str(node.ExecCommand(
                    "consul acl token create -policy-name 'agent_policy' -token %s |awk 'FNR == 2 {print $2}'"
                    % master_token)))
                agent_token = atoken[0].strip()

                node.ExecCommand(anonymous_policy_command, True)
                node.ExecCommand(
                    "consul acl policy create -name 'anonymous' -rules @anonymous_policy_file.hcl -token %s"
                    % master_token)
                atoken = re.findall(regexp, str(node.ExecCommand(
                    "consul acl token update -policy-name 'anonymous' -id %s "
                    "-token %s |awk 'FNR == 2 {print $2}'" % (anonymous_id, master_token))))

                node.ExecCommand(vault_policy_command, True)
                node.ExecCommand(
                    "consul acl policy create -name 'vault_policy' -rules @vault_policy_file.hcl -token %s"
                    % master_token)
                vtoken = re.findall(regexp, str(node.ExecCommand(
                    "consul acl token create -policy-name 'vault_policy' -token %s |awk 'FNR == 2 {print $2}'"
                    % master_token)))
                vault_token = vtoken[0].strip()

                node.ExecCommand(nginx_policy_command, True)
                node.ExecCommand(
                    "consul acl policy create -name 'nginx_policy' -rules @nginx_policy_file.hcl -token %s"
                    % master_token)
                ntoken = re.findall(regexp, str(node.ExecCommand(
                    "consul acl token create -policy-name 'nginx_policy' -token %s |awk 'FNR == 2 {print $2}'"
                    % master_token)))
                nginx_token = ntoken[0].strip()
            break
    if agent_token is not None:
        print("Sleeping for a few seconds until Agent Token is updated in all Consul cluster members...\n")
        for n in nodes:
            node = n['node_client']
            n['config_hcl_command'] = n['config_hcl_command'].replace("@@@AGENT_TOKEN@@@", "%s" % agent_token)
            node.ExecCommand(n['config_hcl_command'], True)
            node.ExecCommand("sudo service consul restart", True)
            time.sleep(2)
    print("Setting up HashiCorp VAULT Secret Management Tool Service...")
    time.sleep(2)
    for n in nodes:
        node = n['node_client']
        if n['Server'] == 'vault':
            if not os.path.exists(vaultBinary):
                print("Cannot find vault binary")
            node.SendFile(vaultBinary, "vault")
            print("Succesfully Coppied vault Binary to node:%s " % n['hostname'])
            config_vault = str(Create_Vault_Config_File)
            config_vault = config_vault.replace(
                "@@@TLS@@@", "true")
            config_vault = config_vault.replace(
                "@@@VAULT_TOKEN@@@", "%s" % vault_token)
            config_vault = config_vault.replace(
                "@@@VAULT_SERVER_IP@@@", "%s" % n['ip_address'])
            n['config_vault_command'] = config_vault
            node.ExecCommand("sudo systemctl stop vault", True)
            node.ExecCommand("sudo rm -rf /opt/vault", True)
            node.ExecCommand("sudo mkdir --parents /opt/vault", True)
            node.ExecCommand(
                "sudo useradd --system --home /etc/vault.d --shell /bin/false vault", True)
            node.ExecCommand("sudo chown --recursive vault:vault /opt/vault", True)
            node.ExecCommand("sudo rm -rf /opt/vault/*", True)
            node.ExecCommand("sudo chmod a+x vault")
            node.ExecCommand("sudo mv vault /usr/local/bin", True)
            node.ExecCommand("sudo mkdir /etc/vault.d", True)
            node.ExecCommand("sudo chmod a+w /etc/vault.d", True)
            node.ExecCommand(
                "sudo chown --recursive vault:vault /etc/vault.d", True)
            node.ExecCommand(
                "sudo vault -autocomplete-install", True)
            node.ExecCommand(
                "sudo complete -C /usr/local/bin/vault vault", True)
            node.ExecCommand(config_vault, True)
            node.ExecCommand(Create_Vault_Service_Command, True)
            node.ExecCommand("sudo systemctl enable vault", True)
            node.ExecCommand("sudo systemctl daemon-reload", True)
            node.ExecCommand("sudo service vault stop", True)
            print('Starting Vault Service on node: %s' % n['hostname'])
            node.ExecCommand("sudo service vault start", True)
            print("Sleeping for 5 seconds until Vault Server %s is ready..." % n['hostname'])
            time.sleep(5)
    print("")
    for n in nodes:
        node = n['node_client']
        if n['Server'] == 'vault':
            print("Initializing Vault Service on node: ", n['hostname'])
            vault_secrets = node.ExecCommand(
                "sudo vault operator init -address=\"http://127.0.0.1:8200\" |tee Vault.Secrets", True)

            with open('Vault.Secrets', 'w') as the_file:
                the_file.writelines(vault_secrets['out'])
                print("Saved Vault.Secrets locally")
            break

    regexp1 = r'Unseal Key [\d]+: ([^\n]+)'
    regexp2 = r'Initial Root Token: ([^\n]+)'
    keys = []
    with open('Vault.Secrets', 'r') as the_file:
        for line in the_file:
            if "Unseal" in line:
                keys.append(re.findall(regexp1, line))
            if "Root Token" in line:
                rtoken = re.findall(regexp2, line)
    print("Vault Root Token -> %s \n" % rtoken[0])
    for n in nodes:
        node = n['node_client']
        if n['Server'] == 'vault':
            print("Unsealing Vault node: %s..." % n['hostname'])
            node.ExecCommand(
                "vault operator unseal -address=\"http://127.0.0.1:8200\" %s" % keys[1][0], True)
            node.ExecCommand(
                "vault operator unseal -address=\"http://127.0.0.1:8200\" %s" % keys[2][0], True)
            node.ExecCommand(
                "vault operator unseal -address=\"http://127.0.0.1:8200\" %s" % keys[3][0], True)
            time.sleep(2)

    regexp3 = r'out\': \[\'([^\\]+)'
    for n in nodes:
        node = n['node_client']
        if n['Server'] == "vault":
            print("Checking Vault Status on %s -> " % n['hostname'], end='')
            file_name = n['hostname'] + ".status"
            time.sleep(2)
            node.ExecCommand("vault status -address=\"http://127.0.0.1:8200\" | sudo tee %s" % file_name)
            node.GetFile(file_name, os.getcwd() + "/%s" % file_name)
            with open(file_name, 'r') as the_file:
                status_str = the_file.read()
                if re.search("active", status_str):
                    print("Active \n")
                    node.ExecCommand("vault login -address=\"http://127.0.0.1:8200\" %s" % rtoken[0])
                    # print("Enabling Consul Engine on Vault for ACL Management")
                    # node.ExecCommand("vault secrets enable -address=\"http://127.0.0.1:8200\" consul")
                    # node.ExecCommand("vault write -address=\"http://127.0.0.1:8200\" "
                    #                  "consul/config/access address=127.0.0.1:8500 token=%s" % master_token)
                    # time.sleep(2)

                    print("Creating a policy and token for PKI Secret Engine...")
                    node.ExecCommand("sudo %s" % str(PKI_Policy_File), True)
                    node.ExecCommand("vault policy write -address=\"http://127.0.0.1:8200\" "
                                     "pki_policy pki_policy_file.hcl", True)
                    pki_token = re.findall(regexp3, str(node.ExecCommand("vault token create "
                                                                         "-address=\"http://127.0.0.1:8200\" "
                                                                         "-policy=pki_policy |awk 'FNR == 3 {print $2}'")))
                    # print("PKI Token -> ", pki_token[0])
                    time.sleep(2)

                    print("Enabling PKI Secret Engine on %s..." % n['hostname'])
                    node.ExecCommand("vault secrets enable -address=\"http://127.0.0.1:8200\" pki")
                    node.ExecCommand("vault secrets tune -address=\"http://127.0.0.1:8200\" "
                                     "-max-lease-ttl=219000h pki")
                    print("Generating PKI Root Certificate...\n")
                    time.sleep(2)
                    node.ExecCommand("vault write -address=\"http://127.0.0.1:8200\" "
                                     "-field=certificate pki/root/generate/internal common_name=\"consul\" "
                                     "ttl=219000h > Root_CA_cert.crt")
                    node.ExecCommand(
                        "vault write -address=\"http://127.0.0.1:8200\" pki/config/urls "
                        "issuing_certificates=\"http://127.0.0.1:8200/v1/pki/ca\" "
                        "crl_distribution_points=\"http://127.0.0.1:8200/v1/pki/crl\"")
                    time.sleep(1)
                    print("Enabling Intermediate PKI Secret Engine on %s..." % n['hostname'])
                    node.ExecCommand("vault secrets enable -address=\"http://127.0.0.1:8200\" -path=pki_int pki")
                    node.ExecCommand(
                        "vault secrets tune -address=\"http://127.0.0.1:8200\" -max-lease-ttl=175200h pki_int")

                    print("Generating Intermediate Root Certificate...\n")
                    node.ExecCommand(
                        "vault write -address=\"http://127.0.0.1:8200\" -format=json "
                        "pki_int/intermediate/generate/internal common_name=\"Consul Intermediate Authority\" "
                        "ttl=\"175200h\" | jq -r '.data.csr' > pki_intermediate.csr")
                    node.ExecCommand(
                        "vault write -address=\"http://127.0.0.1:8200\" -format=json "
                        "pki/root/sign-intermediate csr=@pki_intermediate.csr format=pem_bundle "
                        "ttl=\"175200h\" | jq -r '.data.certificate' > intermediate.cert.pem")
                    node.ExecCommand(
                        "vault write -address=\"http://127.0.0.1:8200\" "
                        "pki_int/intermediate/set-signed certificate=@intermediate.cert.pem")
                    time.sleep(2)

                    print("Creating PKI roles named \"consul-role\" and \"leaf-cert\" for PKI_INT path...\n")
                    node.ExecCommand("vault write -address=\"http://127.0.0.1:8200\" "
                                     "pki_int/roles/consul-role allow_subdomain=true allowed_domains=\"consul\" "
                                     "key_type=ec key_bits=224 require_cn=false use_csr_sans=false ttl=1h max_ttl=8760h")
                    node.ExecCommand("vault write  -address=\"http://127.0.0.1:8200\" "
                                     "pki_int/roles/leaf-cert allow_subdomain=true allowed_domains=consul "
                                     "key_type=ec key_bits=224 require_cn=false use_csr_sans=false ttl=1h max_ttl=1h")
                    time.sleep(2)
                    break
                else:
                    print("Standby \n")

    for n in nodes:
        node = n['node_client']
        if n['Server'] == 'nginx':
            print("Configuring NGINX on node: %s .." % n['hostname'])
            index_file = str(Create_Nginx_Index_File)
            index_file = index_file.replace("@@@NGINX-HOST@@@", n['hostname'])
            node.ExecCommand(index_file, True)
            node.ExecCommand("sudo systemctl enable nginx.service", True)
            node.ExecCommand("sudo systemctl restart nginx.service", True)
            nginx_service = str(Create_Nginx_Service_Command)
            nginx_service = nginx_service.replace("@@@NGINX_TOKEN@@@", "%s" % nginx_token)
            nginx_service = nginx_service.replace("@@@NGINX-IP@@@", n['ip_address'])
            node.ExecCommand(nginx_service, True)
    print("")

    if datacenter['pki_engine'] == 'vault':
        print("Configuring Vault as PKI Engine to generate TLS certificates...\n")
    else:
        print("Configuring Consul Built-in TLS...\n")

    for n in nodes:
        node = n['node_client']
        connect_config = str(Connect_Consul_Config_File)
        if datacenter['pki_engine'] == 'vault':
            if n['Server'] == 'consul':
                connect_config = str(Connect_Config_File)
                connect_config = connect_config.replace("@@@VAULT-TOKEN@@@", "%s" % pki_token[0])
        node.ExecCommand("sudo %s" % connect_config, True)
        print("Restarting consul service on Node: %s " % n['hostname'])
        node.ExecCommand("sudo systemctl restart consul.service", True)

    num1 = 0
    num2 = 0
    tls_created = None
    for n in nodes:
        node = n['node_client']
        tls_config_command = str(TLS_Config_File)
        n['copied'] = None
        if n['Server'] == 'consul':
            if tls_created is not True:
                for num in range(totalConsulServers):
                    if num == 0:
                        node.ExecCommand("consul tls ca create")
                        node.GetFile("consul-agent-ca.pem", tlsCerts + "/consul-agent-ca.pem")
                        node.ExecCommand("consul tls cert create -server")
                        node.ExecCommand("sudo cp *.pem /etc/consul.d/", True)
                        n['copied'] = True
                    else:
                        node.ExecCommand("consul tls cert create -server")
                        tls_cert = primary_dc_name + "-server-consul-" + str(num) + ".pem"
                        tls_key = primary_dc_name + "-server-consul-" + str(num) + "-key.pem"
                        node.GetFile(tls_cert, tlsCerts + tls_cert)
                        node.GetFile(tls_key, tlsCerts + tls_key)

                for num in range(totalVaultServers + totalNginxServers):
                    node.ExecCommand("consul tls cert create -client")
                    tls_cert = primary_dc_name + "-client-consul-" + str(num) + ".pem"
                    tls_key = primary_dc_name + "-client-consul-" + str(num) + "-key.pem"
                    node.GetFile(tls_cert, tlsCerts + tls_cert)
                    node.GetFile(tls_key, tlsCerts + tls_key)
                print("Succesfully CREATED TLS Certs on node: %s " % n['hostname'])
                tls_created = True

            tls_cert = primary_dc_name + "-server-consul-" + str(num1) + ".pem"
            tls_key = primary_dc_name + "-server-consul-" + str(num1) + "-key.pem"
            tls_config_command = tls_config_command.replace("@@@TLS-CERT@@@", "%s" % tls_cert)
            tls_config_command = tls_config_command.replace("@@@TLS-KEY@@@", "%s" % tls_key)
            n['tls_config_command'] = tls_config_command
            node.ExecCommand(n['tls_config_command'], True)
            node.ExecCommand("sudo sed -i 's/http/https/' /etc/consul.d/consul.hcl")
            node.ExecCommand("sudo sed -i 's/dns/https \= 8501, dns/' /etc/consul.d/consul.hcl")
            if n['UI']:
                node.ExecCommand("sudo sed -i '/ui = true/a client_addr = \"0.0.0.0\"' /etc/consul.d/consul.hcl")
                node.ExecCommand(
                    "sudo echo \"enable_script_checks = false\" >> /etc/consul.d/consul.hcl")
                node.ExecCommand("sudo echo \"disable_remote_exec = true\" >> /etc/consul.d/consul.hcl")
                node.ExecCommand("sudo sed -i '/verify_incoming/ s/true/false/' /etc/consul.d/tls_config_file.json", True)
                node.ExecCommand("sudo sed -i '/verify_incoming/a \"verify_incoming_rpc\": true,' "
                                 "/etc/consul.d/tls_config_file.json", True)
            if n['copied'] is True:
                node.ExecCommand("sudo systemctl restart consul.service", True)
                num1 += 1
                continue
            else:
                node.SendFile(tlsCerts + "consul-agent-ca.pem", "consul-agent-ca.pem")
                node.SendFile(tlsCerts + tls_cert, tls_cert)
                node.SendFile(tlsCerts + tls_key, tls_key)
                node.ExecCommand("sudo mv *.pem /etc/consul.d/", True)
                node.ExecCommand("sudo systemctl restart consul.service", True)
                print("Succesfully Coppied TLS Certs to node: %s " % n['hostname'])
                n['copied'] = True
                num1 += 1
        else:
            tls_cert = primary_dc_name + "-client-consul-" + str(num2) + ".pem"
            tls_key = primary_dc_name + "-client-consul-" + str(num2) + "-key.pem"
            tls_config_command = tls_config_command.replace("@@@TLS-CERT@@@", "%s" % tls_cert)
            tls_config_command = tls_config_command.replace("@@@TLS-KEY@@@", "%s" % tls_key)
            n['tls_config_command'] = tls_config_command
            node.ExecCommand(n['tls_config_command'], True)
            node.ExecCommand("sudo sed -i 's/http/https/' /etc/consul.d/consul.hcl")
            node.ExecCommand("sudo sed -i 's/dns/https \= 8501, dns/' /etc/consul.d/consul.hcl")
            node.SendFile(tlsCerts + "consul-agent-ca.pem", "consul-agent-ca.pem")
            node.SendFile(tlsCerts + tls_cert, tls_cert)
            node.SendFile(tlsCerts + tls_key, tls_key)
            node.ExecCommand("sudo mv *.pem /etc/consul.d/", True)
            node.ExecCommand("sudo systemctl restart consul.service", True)
            print("Succesfully Coppied TLS Certs to node: %s " % n['hostname'])
            if n['Server'] == 'vault':
                # node.ExecCommand("sudo cat /etc/consul.d/%s > /etc/vault.d/%s_cert.pem" %(tls_cert, n['hostname']), True)
                # node.ExecCommand("sudo cat /etc/consul.d/consul-agent-ca.pem >> /etc/vault.d/%s_cert.pem" % n['hostname'], True)
                # node.ExecCommand("sudo cat /etc/consul.d/%s > /etc/vault.d/%s_key.pem" % (tls_key, n['hostname']),
                #                  True)
                # node.ExecCommand("sudo sed -i '/tls_disable/a tls_key_file = \"/etc/vault.d/%s_key.pem\"' /etc/vault.d/vault.hcl" % n['hostname'], True)
                # node.ExecCommand(
                #     "sudo sed -i '/tls_disable/a tls_cert_file = \"/etc/vault.d/%s_cert.pem\"' /etc/vault.d/vault.hcl" %
                #     n['hostname'], True)
                # node.ExecCommand(
                #     "sudo sed -i '/tls_disable/d' /etc/vault.d/vault.hcl", True)
                node.ExecCommand("sudo sed -i 's/8500/8501/' /etc/vault.d/vault.hcl", True)
                node.ExecCommand("sudo sed -i '/storage/a   scheme = \"https\"' /etc/vault.d/vault.hcl", True)
                node.ExecCommand("sudo sed -i "
                                 "'/token/a   tls_key_file = \"/etc/consul.d/%s\"' /etc/vault.d/vault.hcl" % tls_key,
                                 True)
                node.ExecCommand("sudo sed -i "
                                 "'/token/a   tls_cert_file = \"/etc/consul.d/%s\"' /etc/vault.d/vault.hcl" % tls_cert,
                                 True)
                node.ExecCommand("sudo sed -i "
                                 "'/token/a   tls_ca_file = \"/etc/consul.d/consul-agent-ca.pem\"' /etc/vault.d/vault.hcl",
                                 True)
                node.ExecCommand("sudo systemctl restart vault", True)
                print("Unsealing Vault node: %s..." % n['hostname'])
                time.sleep(5)
                node.ExecCommand(
                    "vault operator unseal -address=\"http://127.0.0.1:8200\" %s" % keys[1][0], True)
                node.ExecCommand(
                    "vault operator unseal -address=\"http://127.0.0.1:8200\" %s" % keys[2][0], True)
                node.ExecCommand(
                    "vault operator unseal -address=\"http://127.0.0.1:8200\" %s" % keys[3][0], True)
            num2 += 1

if UpDateConfigFileWhenFinished:
    print("updating original nodes.config.json with updated configurations")
    os.rename('nodes.config.json', 'nodes.config.json.old')
    with open('nodes.config.json', 'w') as the_file:
        the_file.write(json.dumps(config_backUp, indent=2))
