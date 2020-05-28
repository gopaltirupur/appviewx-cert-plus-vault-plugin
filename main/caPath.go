package main

import (
	"appviewx-cert-plus-vault-plugin/appviewx/ca"
	"appviewx-cert-plus-vault-plugin/appviewx/common"
	"context"
	"log"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func getPathForCaAppViewX(b backend) *framework.Path {
	return &framework.Path{
		Pattern: "ca/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: `Specifies the Name of the CA Config`,
			},
			"certificate_authority": {
				Type:        framework.TypeString,
				Description: `Specifies the Name Certificate Authority`,
			},
			"ca_setting_name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Specifies the CA Setting Name`,
			},
			"vendor_specific_details": &framework.FieldSchema{
				Type:        framework.TypeKVPairs,
				Description: `Specifies Vendor Specific Details`,
			},
			"division_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Specifies the Division Id`,
			},
			"certificate_type": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Specifies the Certificate Type`,
			},
			"connector_name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Specifies the Connector Name`,
			},
			"description": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Specifies the Description`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathReadCaAppViewX,
			logical.UpdateOperation: b.pathCreateCaAppViewX,
			logical.DeleteOperation: b.pathDeleteCaAppViewX,
		},
		HelpSynopsis:    apviewxIssueCertificate,
		HelpDescription: apviewxIssueCertificate,
	}
}

func (b *backend) pathReadCaAppViewX(context context.Context, request *logical.Request, data *framework.FieldData) (output *logical.Response, err error) {

	defer common.GlobalRecovery("pathReadCaAppViewX")

	configName := data.Get("name").(string)
	log.Println("Getting Config for the Name :", configName)
	if configName == "" {
		return logical.ErrorResponse("Missing the Config Name"), nil
	}

	ca, err := b.getCa(context, request.Storage, configName)
	if err != nil {
		log.Println("Error in b.getCa : ", err)
		return nil, err
	}
	if ca == nil {
		return nil, nil
	}
	output = &logical.Response{
		Data: ca.GenerateResponseData(),
	}
	return
}

func (b *backend) pathCreateCaAppViewX(context context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Println("Reached pathCreateCaAppViewX")

	defer common.GlobalRecovery("pathCreateCaAppViewX")

	caName := data.Get("name").(string)

	ca := &ca.CA{
		CertificateAuthority: data.Get("certificate_authority").(string),
		CaSettingName:        data.Get("ca_setting_name").(string),
		// VendorSpecificDetails: common.GetMapForString(data.Get("vendor_specific_details").(string)),
		VendorSpecificDetails: data.Get("vendor_specific_details").(map[string]string),
		DivisionId:            data.Get("division_id").(string),
		CertificateType:       data.Get("certificate_type").(string),
		ConnectorName:         data.Get("connector_name").(string),
		Description:           data.Get("description").(string),
	}

	caJson, err := logical.StorageEntryJSON("ca/"+caName, ca)
	if err != nil {
		log.Println("Error in pathCreateCaAppViewX : logical.StorageEntryJSON :", err)
		return nil, err
	}

	if err := request.Storage.Put(context, caJson); err != nil {
		log.Println("Error in pathCreateCaAppViewX : request.Storage.Put", err)
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathDeleteCaAppViewX(context context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	defer common.GlobalRecovery("pathDeleteCaAppViewX")

	err := request.Storage.Delete(context, "ca/"+data.Get("name").(string))
	if err != nil {
		log.Println("Error in pathDeleteCaAppViewX : request.Storage.Delete", err)
		return nil, err
	}
	return nil, nil
}

func (b *backend) getCa(context context.Context, storage logical.Storage, name string) (output *ca.CA, err error) {
	log.Println("Path : ", "ca/"+name)

	entry, err := storage.Get(context, "ca/"+name)
	if err != nil {
		log.Println("Error while getting the ca ", entry, err)
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var result ca.CA
	if err := entry.DecodeJSON(&result); err != nil {
		log.Println("Error in getCa : entry.DecodeJSON : ", err)
		return nil, err
	}
	return &result, nil
}
