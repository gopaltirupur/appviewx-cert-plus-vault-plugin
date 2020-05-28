package main

import (
	"appviewx-cert-plus-vault-plugin/appviewx/common"
	"context"
	"log"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

//WIP
func getPathForDiscoveryOfCertificatesFromVault(b backend) *framework.Path {
	return &framework.Path{
		Pattern: "discovery/" + "(?P<certificate_path>\\w(([\\w-/.]+)?\\w)?)",
		// Pattern: "discovery/" + framework.GenericNameRegex("certificate_path"),
		Fields: map[string]*framework.FieldSchema{
			"certificate_path": {
				Type:        framework.TypeString,
				Description: "Path for the proposed discovery",
			},
			"key": {
				Type:        framework.TypeString,
				Description: "Key for getting certificate",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.discoveryOfCertificatesReadAndWriteToAppViewX,
		},
		HelpSynopsis:    "Discovery of Certificates fromt the vault",
		HelpDescription: "Discovery of Certificates fromt the vault",
	}
}

func (b *backend) discoveryOfCertificatesReadAndWriteToAppViewX(context context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	defer common.GlobalRecovery("discoveryOfCertificatesReadAndWriteToAppViewX")

	certificatePath := data.Get("certificate_path").(string)

	//TODO:  - to remove
	log.Println("certificatePath : ", certificatePath)

	key := data.Get("key").(string)
	log.Println("key : ", key)

	log.Println("Reached discoveryOfCertificatesReadAndWriteToAppViewX")
	log.Println("certificatePath : ", certificatePath)

	certificatesList, err := request.Storage.List(context, certificatePath)
	if err != nil {
		log.Println("Error received while fetching the certificates from the path given : Path : ", certificatePath, err)
		return nil, err
	}

	if len(certificatesList) <= 0 {
		log.Println("No Certificates Present in the given path ")
		return nil, nil
	}

	for _, certificate := range certificatesList {
		log.Println(certificate)
	}
	return nil, nil
}
