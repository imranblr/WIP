#!/usr/bin/python3
from classes.node import node
import json
import os
import time
import copy
import re
import uuid
consulBinary = "/home/imran/VagrantProjects/Infra/automation/binaries/consul"
vaultBinary = "/home/imran/VagrantProjects/Infra/automation/binaries/vault"

Create_Service_Command = """
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
ExecStart=/usr/local/bin/consul agent -config-dir=/etc/consul.d/
ExecReload=/usr/local/bin/consul reload
KillMode=process
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi
"""


Create_Consul_Server_Config_File = """
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
connect = {
  enabled = true
}
@@@PRIMARY_DATACENTER_NAME@@@
acl = {
  #@@@ACL_ENABLE@@@
  default_policy = "deny"
  down_policy = "extend-cache"
  tokens = {
      default = "@@@AGENT_TOKEN@@@"
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

Agent_Policy_File = """
cat << EOM | sudo tee agent_policy_file.hcl
node_prefix "" {
   policy = "write"
}

service_prefix "" {
   policy = "write"
}
EOM
"""

config = None
try:
 with open("nodes.config.json") as f:
    config = json.loads(f.read())

except:
 print("Configuration file is missing")     

#if config is None:
#    print("kiss my ass")
#    exit(1)


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

    consul_nodes = datacenter['consul_nodes']
    totalConsulServers = 0
    retry_join_string = ""
    for n in consul_nodes:
        if n['Server']:
            totalConsulServers += 1
            retry_join_string += '"' + n['ip_address'] + '"' + ", "

    if totalConsulServers < 3:
        print("Invalid number of consul nodes, minimum 3, recommened 5")
        exit(1)

    join_string = ""
    for cn in consul_nodes:
        join_string += cn['ip_address'] + " "

    for n in consul_nodes:
        newNode = None
        if n['ssh_password']:
            newNode = node(n['ip_address'], n['ssh_port'],
                           n['ssh_username'], password=n['ssh_password'])
        elif n['ssh_keyfile']:
            newNode = node(n['ip_address'], n['ssh_port'],
                           n['ssh_username'], keyfile=n['ssh_keyfile'])
        print("Testing Connection Node: %s" % n['hostname'])
        if newNode:
            if newNode.Connect():
                n['node_client'] = newNode
                print('Stopping Consul Service on node: %s' % n['hostname'])
                newNode.ExecCommand("sudo service consul stop", True)
                # print(n['node_client'])
                # print(newNode.ExecCommand("apt update", True))
                # exit(0)
    # Copy Consul Binary for each node
    for n in consul_nodes:
        node = n['node_client']
        'node type: node'
        if not os.path.exists(consulBinary):
            print("Cannot find consul binary")
        # we have to create a real config.hcl string now
        # make a copy of the original string
        config_hcl = str(Create_Consul_Server_Config_File)

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

        if n['Server']:
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
#        config_hcl = config_hcl.replace(
#            "@@@AGENT_MASTER@@@", str(uuid.uuid4()))
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
        node.SendFile(consulBinary, "consul")
        print("Succesfully Coppied Consul Binary to node:%s " % n['hostname'])
        node.ExecCommand("sudo apt install -y unzip curl jq dnsutils uuid", True)
        node.ExecCommand("sudo rm -rf /opt/consul", True)
        result = node.ExecCommand("hostname")
        if result['out'][0].strip() != n['hostname']:
            print("Original hostname is: %s, Wanted Hostname: %s, We have to change it" % (
                result['out'][0].strip(), n['hostname']))
            node.ExecCommand("sudo  hostnamectl set-hostname %s" %
                             n['hostname'], True)
            RequiresReboot = True
        node.ExecCommand("sudo systemctl stop consul", True)
        node.ExecCommand("sudo hostnamectl set-hostname", True)
        node.ExecCommand("sudo mkdir --parents /opt/consul", True)
        node.ExecCommand("sudo chown --recursive consul:consul /opt/consul", True)
        node.ExecCommand("sudo rm -rf /opt/consul/*", True)
        node.ExecCommand("sudo chmod a+x consul")
        node.ExecCommand("sudo mv consul /usr/local/bin", True)
        node.ExecCommand("sudo mkdir /etc/consul.d", True)
        node.ExecCommand("sudo chmod a+w /etc/consul.d", True)
        node.ExecCommand(
            "sudo useradd --system --home /etc/consul.d --shell /bin/false consul", True)
        node.ExecCommand(
            "sudo chown --recursive consul:consul /etc/consul.d", True)
        node.ExecCommand(
            "sudo consul -autocomplete-install", True)
        node.ExecCommand(
            "sudo complete -C /usr/local/bin/consul consul", True)
        node.ExecCommand(config_hcl, True)
        node.ExecCommand(Create_Service_Command, True)
        node.ExecCommand(
            "sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/consul", True)

        if n['Server']:
            print(
                "DNS on port 53 for node \"%s\" selected, disabling systemd-resolved service" % n['hostname'])
            node.ExecCommand("sudo systemctl stop systemd-resolved", True)
            node.ExecCommand("sudo systemctl disable systemd-resolved", True)
        else:
            print(
                "DNS forwarding set on port 53 for node \"%s\", updating Domain in resolved.conf" % n['hostname'])
            node.ExecCommand("sudo bash -c \"echo DNS=127.0.0.1 >> /etc/systemd/resolved.conf\"")
            node.ExecCommand("sudo bash -c \"echo Domains='~consul' >> /etc/systemd/resolved.conf\"")
            node.ExecCommand("sudo systemctl restart systemd-resolved", True)
            node.ExecCommand("sudo systemctl enable systemd-resolved", True)

        node.ExecCommand("sudo systemctl enable consul", True)
        node.ExecCommand("sudo systemctl daemon-reload", True)
        node.ExecCommand("sudo service consul stop", True)
        if RequiresReboot:
            print("Node %s going to reboot now" % n['hostname'])

    for n in consul_nodes:
        node = n['node_client']
        print('Starting Consul Service on node: %s' % n['hostname'])
        node.ExecCommand("sudo service consul start", True)
    print("Sleeping for 5 seconds until cluster is ready and bootstraped...")
    time.sleep(5)
    for n in consul_nodes:
        if n['Server']:
            node = n['node_client']
            node.ExecCommand("sudo consul join %s" % join_string)
            break
    print("Enabling ACL on all nodes and restarting the servers...")
    for n in consul_nodes:
        node = n['node_client']
        n['config_hcl_command'] = n['config_hcl_command'].replace("#@@@ACL_ENABLE@@@", "enabled = true")
        # TODO: Change confiuration file to
        # node.ExecCommand(n['config_hcl_command'].replace("#@@@ACL_ENABLE@@@", "enabled = true"), True)
        node.ExecCommand(n['config_hcl_command'], True)
        # print("For %s :" % n['hostname'], "\n", n['config_hcl_command'], "\n")
    for n in consul_nodes:
        node = n['node_client']
        node.ExecCommand("sudo service consul restart", True)
    print("Sleeping for another 5 seconds until ACL is ready...")
    time.sleep(5)
    print("running ACL bootstrap on first server node")

    agent_policy_command = str(Agent_Policy_File)
    agent_token = None
    mtoken = None
    atoken = None
    master_token = None
    # regexp = r'SecretID : ([^\n]+)'
    regexp = r'out\': \[\'([^\\n\'\]]+)'

    for n in consul_nodes:
        if n['Server']:
            node = n['node_client']
            result = node.ExecCommand("sudo consul acl bootstrap |tee Master.Token", True)
            # print(result)
            with open('Master.token', 'w') as the_file:
                the_file.writelines(result['out'])
                print("Saved Master.Token locally")
            # print(''.join(result['out']), "\n", result, "\n", result['out'])
            print("Saved on node: %s file Master.Token" % n['hostname'], "\n")
    #     break
    # for n in consul_nodes:
    #     if n['Server']:
    #         node = n['node_client']
            print("Creating Agent_Token and its associated policies..")
            # with open('Master.token', 'r') as the_file:
            #     for line in the_file:
            #         if "SecretID" in line:
            #             mtoken = re.findall(regexp, line)
            #             master_token = mtoken[-1].strip()
            mtoken = re.findall(regexp, str(node.ExecCommand("cat Master.Token | awk 'FNR == 2 {print $2}'")))
            # print(mtoken)
            master_token = mtoken[0].strip()
            if master_token is not None:
                node.ExecCommand(agent_policy_command, True)
                node.ExecCommand(
                    "consul acl policy create -name 'agent_policy' -rules @agent_policy_file.hcl -token %s"
                    % master_token)
                atoken = re.findall(regexp, str(node.ExecCommand(
                    "consul acl token create -policy-name 'agent_policy' -token %s |awk 'FNR == 2 {print $2}'"
                    % master_token)))
                agent_token = atoken[0].strip()
        print("Agent Token:", agent_token, "\n", "Master Token:", master_token)
        break
    if agent_token is not None:
        for n in consul_nodes:
            node = n['node_client']
            n['config_hcl_command'] = n['config_hcl_command'].replace("@@@AGENT_TOKEN@@@", "%s" % agent_token)
            # TODO: Change confiuration file to
            node.ExecCommand(n['config_hcl_command'], True)
            # print("For %s :" % n['hostname'], "\n", n['config_hcl_command'], "\n")
            node.ExecCommand("sudo service consul restart", True)
            print("Sleeping for another 2 seconds until Agent Token is updated...")
            time.sleep(2)

if UpDateConfigFileWhenFinished:
    print("updating original nodes.config.json with updated configurations")
    os.rename('nodes.config.json', 'nodes.config.json.old')
    with open('nodes.config.json', 'w') as the_file:
        the_file.write(json.dumps(config_backUp, indent=2))
