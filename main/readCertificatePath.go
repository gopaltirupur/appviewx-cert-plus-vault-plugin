package main

import (
	"appviewx-cert-plus-vault-plugin/appviewx/common"
	"appviewx-cert-plus-vault-plugin/appviewx/submain"
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

//This path is to read the certificates from the vault
func getPathForCertReadFromVault(b backend) *framework.Path {
	return &framework.Path{
		Pattern: "certs/" + framework.GenericNameRegex("common_name"),
		Fields: map[string]*framework.FieldSchema{
			"common_name": {
				Type:        framework.TypeString,
				Description: "CommonName of desired certificate ",
			},
			"config": {
				Type:        framework.TypeString,
				Description: "name of the config",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCertificateRead,
		},
		HelpSynopsis:    "Certificate Read operation",
		HelpDescription: "Certificate Read Operation",
	}
}

func (b *backend) pathCertificateRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	defer common.GlobalRecovery("pathCertificateRead")

	configName := data.Get("config").(string)

	config, err := b.getConfig(ctx, req.Storage, configName)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse(fmt.Sprintf("Config unavailable %s", configName)), nil
	}

	log.Println("Reading Certificate")
	log.Println(data)
	commonName := data.Get("common_name").(string)
	if len(commonName) == 0 {
		return logical.ErrorResponse("no common name specified"), nil
	}

	entry, err := req.Storage.Get(ctx, "certs/"+commonName)
	if err != nil {
		return nil, fmt.Errorf("Certificate Read Failed")
	}
	var storedCertificate ForStorageCertificate

	err = entry.DecodeJSON(&storedCertificate)
	if err != nil {
		return nil, fmt.Errorf("Decode error")
	}

	if !storedCertificate.Status {

		log.Println("***************** Certificate Not Available - Trying to Get from AppViewX ********************** ")
		isAllAvailable, finalSerialNumber, certificateOutput, uuid, err := submain.DownloadCertificateForCertificateID(storedCertificate.CertificateID, config)
		if err != nil {
			log.Println("Error at submain.DownloadCertificateForCertificateID :", err)
			return nil, err
		}

		if isAllAvailable {
			submain.DefaultAppConnector(config, uuid)
		}

		storedCertificate.Status = isAllAvailable
		storedCertificate.SerialNumber = finalSerialNumber
		storedCertificate.Certificate = string(certificateOutput)

		entry, err = logical.StorageEntryJSON("", storedCertificate)
		entry.Key = "certs/" + commonName
		if err := req.Storage.Put(ctx, entry); err != nil {
			log.Println("error while putting in storage", err)
			return nil, err
		} else {
			log.Println("storage successful ")
		}

	}

	response := map[string]interface{}{
		"certificate":   storedCertificate.Certificate,
		"common_name":   storedCertificate.CommonName,
		"alternatives":  storedCertificate.AltNames,
		"private_key":   storedCertificate.PrivateKey,
		"csr":           storedCertificate.CSR,
		"status":        storedCertificate.Status,
		"serial_number": storedCertificate.SerialNumber,
	}
	return &logical.Response{
		Data: response,
	}, nil
}
