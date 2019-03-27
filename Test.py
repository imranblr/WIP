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
# config = None
# try:
#  with open("mnodes.config.json") as f:
#     config = json.loads(f.read())
# except:
#  print("Configuration file error")
# copy_config=copy.deepcopy(config)
# for datacenter in copy_config:
#     print (datacenter['consul_nodes'][4]['ip_address'],"\n",datacenter['domain'])

with open("Vault.Status", 'r') as the_file:
    status_str=the_file.read()
    if re.search("active", status_str):
        print("Found")
