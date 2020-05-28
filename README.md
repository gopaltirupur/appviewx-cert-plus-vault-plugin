## **AppViewX - Hashicorp Vault - PKI - Plugin**

This plugin is to generate the certificates from Vault using AppViewX.

### ***Features***
1. Certificate - Create, Read, List Operations
2. Config - Create, Read, List Operations ( AppViewX Environment )



### ***Installation***
1. Move the plugin to ' plugins ' folder

2. Specify the plugins folder in vault configuration file.
``` 
	#--------------------------------------------
	#config.hcl
	#--------------------------------------------
	plugin_directory = "/root/vault/plugins"

	ui = true

	storage "file" {
		  	path = "/root/vault/vault-data"
	}
```
3. Start the vault by specifying the '.hcl' configuration file
```
./vault-1.2.3 server -log-level=debug -dev -config=vault-config.hcl > ./logs/vault-server.log 2>&1 &
```
4. Set the Environment Variable
```
export VAULT_ADDR=http://127.0.0.1:8200
```
5. Generate the SHA256 value for the new plugin ('vault-cert-plugin')
```
export SHA256=$(shasum -a 256 ./plugins/vault-cert-plugin| cut -d' ' -f1)
```
6. Write the generated SHA256 value in to Vault
```
./vault-1.2.3 write sys/plugins/catalog/secret/vault-cert-plugin sha_256="${SHA256}" command="vault-cert-plugin"
```
7. Enable the plugin
```
./vault-1.2.3 secrets enable -path=appviewx-pki -plugin-name=vault-cert-plugin plugin
```
------

### ***Config for AppViewX Environment***
1. Create Config for AppViewX Environment 
```
./vault-1.2.3 write appviewx-pki/config/appviewx_218 ip=192.168.96.218 port=5300 user_name=admin is_https=true password=AppViewX@123
```

2. Read the Config Created
```
./vault-1.2.3 read appviewx-pki/config/appviewx_218
```

3. List the Config Created
```
./vault-1.2.3 list appviewx-pki/config
```

### ***Example Set***
------
>#### CONFIG ####
*	CREATE 
	```
	./vault-1.2.3 write appviewx-pki/config/appviewx_3_15_144_7 ip=3.15.144.7 port=5300 user_name=admin is_https=true password=AppViewX@123;
	```
*	LIST
	```
	./vault-1.2.3 list appviewx-pki/config
	```
*	READ
	```
	./vault-1.2.3 read appviewx-pki/config/appviewx_3_15_144_7
	```

------

>#### CA ####
* CREATE
	*	APPVIEWX
		```
		./vault-1.2.3 write appviewx-pki/ca/ca_appviewx certificate_authority=AppViewX ca_setting_name="AppViewX CA" certificate_type="server" description="description";
		```
	*	DIGICERT
		```
		./vault-1.2.3 write appviewx-pki/ca/ca_digicert certificate_authority=DigiCert ca_setting_name="DigiCert_CA" vendor_specific_details={caCertId=741B2D2F05C7F6543EFB,orderId=8479058,serverType=Apache} division_id=80312 certificate_type="Private SSL Plus" connector_name="DigiCert Private SSL Plus connector" description="description";
		```
	*	ENTRUST
		```
		./vault-1.2.3 write appviewx-pki/ca/ca_entrust certificate_authority=Entrust ca_setting_name="MarriottTestSubCA1" vendor_specific_details={caName=MarriottTestSubCA1,certProfile="TLS Client & Serv Auth Cert Exp"} division_id=80312 certificate_type="Standard" connector_name="Entrust CA connector" description="description";
		```
*	LIST
	```
	./vault-1.2.3 list appviewx-pki/ca
	```
*	READ
	```
	./vault-1.2.3 read appviewx-pki/ca/ca_appviewx
	```

------

> #### CERT_SETTINGS ####
*	CREATE
	```
	./vault-1.2.3 write appviewx-pki/cert_settings/marriott_digicert_settings file=C:\\fakepath\\testdigicert.appviewx.com.csr hash_function=SHA256  key_type=RSA   bit_length=2048 mail_address=aravind.b@appviewx.com country=US organization="AppViewX Inc." organization_unit="Avx" certificate_categories=Server certificate_groupName=Default category=Server validity_in_days=365;
	```
*	LIST
	```
	./vault-1.2.3 list appviewx-pki/cert_settings
	```
*	READ
	```
	./vault-1.2.3 read appviewx-pki/cert_settings/marriott_digicert_settings
	```

------

>#### CERTIFICATE ####
*	CREATE
	```
	./vault-1.2.3 write appviewx-pki/issue/appviewx_3_15_144_7 common_name=testdigicertvault580.appviewx.com ca=ca_appviewx cert_settings=marriott_digicert_settings
	./vault-1.2.3 write appviewx-pki/issue/appviewx_3_15_144_7 common_name=testdigicertvault581.appviewx.com ca=ca_digicert cert_settings=marriott_digicert_settings
	./vault-1.2.3 write appviewx-pki/issue/appviewx_3_15_144_7 common_name=testdigicertvault582.appviewx.com ca=ca_entrust cert_settings=marriott_digicert_settings
	```
*	LIST
	```	
	./vault-1.2.3 list appviewx-pki/certs
	```
*	READ
	```	
	./vault-1.2.3 read -field=certificate appviewx-pki/certs/testdigicertvault580.appviewx.com config=appviewx_3_15_144_7	
	./vault-1.2.3 read -field=certificate appviewx-pki/certs/testdigicertvault581.appviewx.com config=appviewx_3_15_144_7	
	./vault-1.2.3 read -field=certificate appviewx-pki/certs/testdigicertvault582.appviewx.com config=appviewx_3_15_144_7
	```

------------------------------------------------------------------------------------------------
INSTALLATION STEPS - ( WITH TLS )
------------------------------------------------------------------------------------------------
Create Cert 

1. Generate the cert with the hostname of the vault server.
2. Download the certifcate with the trust store certificates.
3. Download the private key.
4. Have both the root and intermediate cert content in cert file named vault-ca.crt
5. Move the sever cert to file named vault.crt
6. Move the private key to file named vault.key
7. Place the vault-ca.crt,vault.crt and vault.key on /root/vault directory

Change the api_addr to vault instance hostname in config.hcl


export VAULT_CACERT=/root/vault/vault-ca.crt
vault server -log-level=trace -config=vault-config.hcl > vault-server.log 2>&1 &
export VAULT_ADDR=https://int-dev-26.appviewxlab.com:8200
vault operator init
Unseal Key 1: zoNcmAyCAJR1A1I/fHDGPnDoAliyr+yedfE96OKjvbYx
Unseal Key 2: zqDLTPExIUDCDlz6ozNfmUukSguceOwkdx0nhM0nraI3
Unseal Key 3: Rs6Sm0QgNX2IDVZ6wSxhUw3QH7haKqzRpy38d+9/Q3W+
Unseal Key 4: 7OYrzN4DkXdqsvOTkLzAFI3oD6oKyPwfJmK4pd3THh5x
Unseal Key 5: 40Yi3xVStd9BaSITO/DJVXm8lPRjpQ2Z6HU/pqe1TYN1

Initial Root Token: s.ZrssoVyzBk5SAGLXz08Jja77

vault operator unseal
export VAULT_TOKEN=s.ZrssoVyzBk5SAGLXz08Jja77

export SHA256=$(sha256sum vault-cert-plugin| cut -d' ' -f1)
[root@int-dev-26 plugins]# vault write -ca-cert=/root/vault/vault-ca.crt --client-cert=/root/vault/vault.crt --client-key=/root/vault/vault.key sys/plugins/catalog/secret/vault-cert-plugin sha_256="${SHA256}" command="vault-cert-plugin"
Success! Data written to: sys/plugins/catalog/secret/vault-cert-plugin

[root@int-dev-26 plugins]# vault secrets enable -path=appviewx-pki -plugin-name=vault-cert-plugin plugin
Success! Enabled the vault-cert-plugin secrets engine at: appviewx-pki/
You have mail in /var/spool/mail/root

[root@int-dev-26 plugins]# vault write appviewx-pki/config/appviewx ip=192.168.96.218 port=5300 user_name=admin is_https=true password=AppViewX@123;
Success! Data written to: appviewx-pki/config/appviewx

[root@int-dev-26 plugins]# vault write appviewx-pki/ca/ca_appviewx certificate_authority=AppViewX ca_setting_name="AppViewX CA" connector_name="AppViewX CA" description="description";
Success! Data written to: appviewx-pki/ca/ca_appviewx

[root@int-dev-26 plugins]# vault write appviewx-pki/cert_settings/appviewx_settings hash_function=SHA256  key_type=RSA bit_length=2048 mail_address=sales@appviewx.com country=US organization="TEST" organization_unit="TEST" certificate_categories=Server certificate_groupName=Default category=Server validity_in_days=365;
Success! Data written to: appviewx-pki/cert_settings/appviewx_settings

------------------------------------------------------------------------------------------------

Supported HashKey Algorithms

RSA
	case "sha160":template.SignatureAlgorithm = x509.SHA1WithRSA
	case "sha256":template.SignatureAlgorithm = x509.SHA256WithRSA
	case "sha384":template.SignatureAlgorithm = x509.SHA384WithRSA
	case "sha512":template.SignatureAlgorithm = x509.SHA512WithRSA
	case "md5":template.SignatureAlgorithm = x509.MD5WithRSA


ECDSA
	case "sha160":template.SignatureAlgorithm = x509.ECDSAWithSHA1
	case "sha256":template.SignatureAlgorithm = x509.ECDSAWithSHA256
	case "sha384":template.SignatureAlgorithm = x509.ECDSAWithSHA384
	case "sha512":template.SignatureAlgorithm = x509.ECDSAWithSHA512

DSA
	case "sha160":template.SignatureAlgorithm = x509.DSAWithSHA1
	case "sha256":template.SignatureAlgorithm = x509.DSAWithSHA256
