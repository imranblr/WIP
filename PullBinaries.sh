#!/bin/bash


cd binaries/
echo
echo "Determining Consul version ..."
CHECKPOINT_URL="https://checkpoint-api.hashicorp.com/v1/check"
if [ -z "$CONSUL_DEMO_VERSION" ]; then
    CONSUL_DEMO_VERSION=$(curl -s "${CHECKPOINT_URL}"/consul | jq .current_version | tr -d '"')
fi
echo
echo "Fetching Consul version ${CONSUL_DEMO_VERSION} ..."

curl -s https://releases.hashicorp.com/consul/${CONSUL_DEMO_VERSION}/consul_${CONSUL_DEMO_VERSION}_linux_amd64.zip -o consul.zip
echo
echo "Retrieving Consul ${CONSUL_DEMO_VERSION} Binary..."
unzip -o consul.zip

echo
echo "Determining  Vault version ..."
if [ -z "$VAULT_DEMO_VERSION" ]; then
    VAULT_DEMO_VERSION=$(curl -sL "https://releases.hashicorp.com/vault/"|grep 'href="/vault'|grep -v beta|sort -Vr|head -1|awk -F "/" '{print $3}')
fi
echo
echo "Fetching Vault version ${VAULT_DEMO_VERSION} ..."
curl -s https://releases.hashicorp.com/vault/${VAULT_DEMO_VERSION}/vault_${VAULT_DEMO_VERSION}_linux_amd64.zip -o vault.zip
echo
echo "Retrieving Vault version ${VAULT_DEMO_VERSION} Binary..."
unzip -o vault.zip
rm -f *.zip
sudo chmod +x * 

echo
echo "The following binaries were pulled successively:"
echo
ls -ltrh

exit
