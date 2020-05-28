package main

import (
	"appviewx-cert-plus-vault-plugin/appviewx/certificate"
	"appviewx-cert-plus-vault-plugin/appviewx/common"
	"appviewx-cert-plus-vault-plugin/appviewx/submain"
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

//This path is to create the certificate via appviewx for the givven user input, ( Private key and csr will be generate with in the vault )
func getPathForIssueCertificateFromViaAppViewX(b backend) *framework.Path {
	return &framework.Path{
		Pattern: "issue/" + framework.GenericNameRegex("config"),
		Fields: map[string]*framework.FieldSchema{
			"config": {
				Type:        framework.TypeString,
				Description: `Config details about the AppViewX Engironment`,
			},
			"common_name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Specifies the CommonName`,
			},
			"dns_names": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: `Specifies the DNS Names`,
			},
			"ip_addresses": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: `Specifies IP Addresses`,
			},
			"rfc_822_names": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: `Specifies IP Addresses`,
			},
			"directory_names": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: `directory_names`,
			},
			"registered_ids": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: `registered_ids`,
			},
			"uniform_resource_identifiers": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: `uniform_resource_identifiers`,
			},
			"other_names": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: `other_names`,
			},
			"ca": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Specifies the CA`,
			},
			"cert_settings": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Specifies the Cert Settings`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.issueCertificateFromViaAppViewX,
		},

		HelpSynopsis:    apviewxIssueCertificate,
		HelpDescription: apviewxIssueCertificate,
	}
}

func displayTheMarshalledOutputInLog(name string, input interface{}) {
	marshalledInput, _ := json.Marshal(input)
	log.Println(name+" : ", string(marshalledInput))
}

func (b *backend) issueCertificateFromViaAppViewX(context context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	defer common.GlobalRecovery("issueCertificateFromViaAppViewX")

	configName := data.Get("config").(string)
	caName := data.Get("ca").(string)
	certSettingsName := data.Get("cert_settings").(string)

	log.Println("configName :", configName)
	log.Println("caName :", caName)
	log.Println("certSettingsName :", certSettingsName)

	//Getting Config Instance
	configInstance, err := b.getConfig(context, request.Storage, configName)
	if err != nil {
		log.Println("Error in issueCertificateFromViaAppViewX : b.getConfig")
		return nil, err
	}
	if configInstance == nil {
		return logical.ErrorResponse(fmt.Sprintf("Config unavailable %s", configName)), nil
	}
	displayTheMarshalledOutputInLog("configInstance : ", configInstance)

	//Getting CA Instance
	caInstance, err := b.getCa(context, request.Storage, caName)
	if err != nil {
		log.Println("Error in issueCertificateFromViaAppViewX : b.getCa")
		return nil, err
	}
	if caInstance == nil {
		return logical.ErrorResponse(fmt.Sprintf("CA unavailable %s", caName)), nil
	}
	displayTheMarshalledOutputInLog("caInstance : ", caInstance)

	//Getting CertSettings Instance
	certificateSettingsInstance, err := b.getCertSettings(context, request.Storage, certSettingsName)
	if err != nil {
		log.Println("Error in issueCertificateFromViaAppViewX : b.getCertSettings")
		return nil, err
	}
	if certificateSettingsInstance == nil {
		return logical.ErrorResponse(fmt.Sprintf("CertificateSettings unavailable %s", certSettingsName)), nil
	}
	displayTheMarshalledOutputInLog("certificateSettingsInstance : ", certificateSettingsInstance)

	currentCertInstance := &certificate.CurrentCert{
		getValutForKeyFromDataString(data, "common_name"),
		getValutForKeyFromDataStringSlice(data, "dns_names"),
		getValutForKeyFromDataStringSlice(data, "ip_addresses"),
		getValutForKeyFromDataStringSlice(data, "rfc_822_names"),
		getValutForKeyFromDataStringSlice(data, "directory_names"),
		getValutForKeyFromDataStringSlice(data, "registered_ids"),
		getValutForKeyFromDataStringSlice(data, "uniform_resource_identifiers"),
		getValutForKeyFromDataStringSlice(data, "other_names"),
	}

	csrContent, privateKey, err :=
		submain.MainPrivateKeyGeneration(currentCertInstance, configInstance, caInstance, certificateSettingsInstance)
	if err != nil {
		log.Println("Error in submain.MainPrivateKeyGeneration : ", err)
		return nil, err
	}

	certificateID, err := submain.MainCertificateGeneration(csrContent, currentCertInstance, configInstance, caInstance, certificateSettingsInstance)
	if err != nil {
		log.Println("Error in submain.MainCertificateGeneration :", err)
		return nil, err
	}

	log.Println("****************** Received the Certificate And Private Key ")

	forStorage := ForStorageCertificate{
		CommonName: data.Get("common_name").(string),
		// AltNames:      getValutForKeyFromDataStringSlice(data, "alt_names"),
		PrivateKey:    string(privateKey),
		CSR:           string(csrContent),
		CertificateID: certificateID,
		Status:        false,
	}

	var entry *logical.StorageEntry

	entry, err = logical.StorageEntryJSON("", forStorage)

	if err != nil {
		return nil, err
	}

	commonName := data.Get("common_name").(string)
	entry.Key = "certs/" + commonName

	if err := request.Storage.Put(context, entry); err != nil {
		log.Println("error while putting in storage", err)
		return nil, err
	} else {
		log.Println("storage successful ")
	}

	output := map[string]interface{}{
		"common_name": data.Get("common_name").(string),
		// "alt_names":      data.Get("alt_names").([]string),
		"certificate_id": certificateID,
	}

	log.Println("********************************************")

	return &logical.Response{
		Data: output,
	}, nil
}
