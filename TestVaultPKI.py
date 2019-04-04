#!/usr/bin/python3
from classes.node import node
import json
import os
import time
import re

pkiCerts = os.getcwd() + "/pkiCerts/"
config = None
try:
 with open("nodes.config_all.json") as f:
    config = json.loads(f.read())

except:
 print("Configuration file is missing")


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

    print("\n  ===> Established connection to all the nodes!!! <=== \n")
    time.sleep(2)

    for n in nodes:
        node = n['node_client']
        'node type: node'
        pki_engine_enabled = None
        if n['Server'] == "vault":
            if pki_engine_enabled is not True:
                print("Checking Vault Status on %s -> " % n['hostname'], end='')
                file_name = n['hostname'] + ".status"
                time.sleep(2)
                node.ExecCommand("vault status -address=\"http://127.0.0.1:8200\" | sudo tee %s" % file_name)
                node.GetFile(file_name, os.getcwd() + "/%s" % file_name)
                with open(file_name, 'r') as the_file:
                    status_str = the_file.read()
                    if re.search("active", status_str):
                        print("Active \n")
                        print("Enabling PKI Secret Engine on %s...\n" % n['hostname'])
                        active_vault_ip = n['ip_address']
                        node.ExecCommand("vault login -address=\"http://127.0.0.1:8200\" %s" % rtoken[0])
                        node.ExecCommand("vault secrets enable -address=\"http://127.0.0.1:8200\" pki")
                        node.ExecCommand("vault secrets tune -address=\"http://127.0.0.1:8200\" "
                                         "-max-lease-ttl=219000h pki")
                        print("Generating root certificate...\n")
                        time.sleep(2)
                        node.ExecCommand("vault write -address=\"http://127.0.0.1:8200\" "
                                         "-field=certificate pki/root/generate/internal common_name=\"consul\" "
                                         "ttl=219000h > Root_CA_cert.crt")
                        node.ExecCommand(
                            "vault write -address=\"http://127.0.0.1:8200\" pki/config/urls "
                            "issuing_certificates=\"http://127.0.0.1:8200/v1/pki/ca\" "
                            "crl_distribution_points=\"http://127.0.0.1:8200/v1/pki/crl\"")
                        time.sleep(1)
                        # print("Testing Root Certificates...\n\n")
                        # ca_cert_out1 = node.ExecCommand("openssl x509 -in CA_cert.crt -text")
                        # print(''.join(ca_cert_out1['out']), "\n")
                        # ca_cert_out2 = node.ExecCommand("openssl x509 -in CA_cert.crt -noout -dates")
                        # print(''.join(ca_cert_out2['out']), "\n\n\n")
                        # time.sleep(2)

                        print("Enabling Intermediate PKI Secret Engine on %s...\n" % n['hostname'])
                        node.ExecCommand("vault secrets enable -address=\"http://127.0.0.1:8200\" -path=pki_int pki")
                        node.ExecCommand(
                            "vault secrets tune -address=\"http://127.0.0.1:8200\" -max-lease-ttl=175200h pki_int")

                        print("Generating Intermediate root certificate...\n")
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

                        print("Creating a role called \"consul-role\"...\n")
                        node.ExecCommand("vault write -address=\"http://127.0.0.1:8200\" "
                                         "pki_int/roles/consul-role allowed_domains=\"consul\" "
                                         "allow_subdomains=true max_ttl=\"8760h\"")
                        time.sleep(2)

                        print("Issuing a certificate ...\n\n")
                        node.ExecCommand("vault write -address=\"http://127.0.0.1:8200\" "
                                         "pki_int/issue/consul-role common_name=\"server.dc1.consul\" "
                                         "ttl=\"8760h\" | sudo tee server.dc1.consul")
                        node.ExecCommand("vault write -address=\"http://127.0.0.1:8200\" "
                                         "pki_int/issue/consul-role common_name=\"client.dc1.consul\" "
                                         "ttl=\"8760h\" | sudo tee client.dc1.consul")
                        time.sleep(2)

                        print("Saving and copying PKI Certs to host machine...")
                        node.ExecCommand("sudo awk '/\[/{a=1}a;/\]/{a=0}' client.dc1.consul "
                                         "| sed 's/ca_chain.*\[//;s/\]//' > CA_cert.pem")
                        node.ExecCommand("sudo awk '/certificate/{a=1}a;/private/{a=0}' server.dc1.consul "
                                         "| sed -e 's/certi.*  //;s/issuin.*  //;/expir.*/d;/private.*/d' "
                                         "> Server_cert.pem")
                        node.ExecCommand("sudo awk '/certificate/{a=1}a;/private/{a=0}' client.dc1.consul "
                                         "| sed -e 's/certi.*  //;s/issuin.*  //;/expir.*/d;/private.*/d' "
                                         "> Client_cert.pem")
                        node.ExecCommand("sudo awk '/private/{a=1}a;/rsa/{a=0}' server.dc1.consul "
                                         "| sed -e 's/priva.*  //;/rsa.*/d' > Server_key.pem")
                        node.ExecCommand("sudo  awk '/private/{a=1}a;/rsa/{a=0}' client.dc1.consul "
                                         "| sed -e 's/priva.*  //;/rsa.*/d' > Client_key.pem")
                        node.GetFile("intermediate.cert.pem", pkiCerts + "intermediate.cert.pem")
                        node.GetFile("CA_cert.pem", pkiCerts + "CA_cert.pem")
                        node.GetFile("Server_cert.pem", pkiCerts + "Server_cert.pem")
                        node.GetFile("Client_cert.pem", pkiCerts + "Client_cert.pem")
                        node.GetFile("Server_key.pem", pkiCerts + "Server_key.pem")
                        node.GetFile("Client_key.pem", pkiCerts + "Client_key.pem")
                        pki_engine_enabled = True
                        break
                    else:
                        print("Standby \n")
    print("Configuring TLS with Vault PKI Certs...")

    for n in nodes:
        node = n['node_client']
        node.SendFile(pkiCerts + "CA_cert.pem", "CA_cert.pem")
        if n['Server'] == 'consul':
            node.SendFile(pkiCerts + "Server_cert.pem", "Server_cert.pem")
            node.SendFile(pkiCerts + "Server_key.pem", "Server_key.pem")
            node.ExecCommand("sudo sed -i 's/consul-agent-ca.pem/CA_cert.pem/' /etc/consul.d/tls_config_file.json", True)
            node.ExecCommand("sudo sed -i 's/dc1.*key/Server_key/' /etc/consul.d/tls_config_file.json", True)
            node.ExecCommand("sudo sed -i 's/dc1.*pem/Server_cert.pem/' /etc/consul.d/tls_config_file.json", True)
        else:
            node.SendFile(pkiCerts + "Client_cert.pem", "Client_cert.pem")
            node.SendFile(pkiCerts + "Client_key.pem", "Client_key.pem")
            node.ExecCommand("sudo sed -i 's/consul-agent-ca.pem/CA_cert.pem/' /etc/consul.d/tls_config_file.json",
                             True)
            node.ExecCommand("sudo sed -i 's/dc1.*key/Client_key/' /etc/consul.d/tls_config_file.json", True)
            node.ExecCommand("sudo sed -i 's/dc1.*pem/Client_cert.pem/' /etc/consul.d/tls_config_file.json", True)

        print("Successfully copied PKI Certs on node: %s" % n['hostname'])
        node.ExecCommand("sudo mv *.pem /etc/consul.d/", True)
        node.ExecCommand("sudo systemctl restart consul.service", True)
