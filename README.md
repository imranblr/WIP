# ConsulVault
After cloning the repository run ->

"vagrant up" => This will start 3 consul, 2 vault, 2 nginx and 1 ssh server

"./PullBinaries.sh" => This will download consul and vault binaries

"./InitNewInfra.py" => This will fully configure consul, vault and nginx to use mTLS

"./TestSSH.py" => This will enable Vault SSH engine and setup vault helper on SSH server
