package main

import (
	"appviewx-cert-plus-vault-plugin/appviewx/certSettings"
	"appviewx-cert-plus-vault-plugin/appviewx/common"
	"context"
	"log"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func getPathForCertSettingsAppViewX(b backend) *framework.Path {
	return &framework.Path{
		Pattern: "cert_settings/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Specifies the name of the Cert Settings",
			},
			"file": {
				Type:        framework.TypeString,
				Description: "",
			},
			"hash_function": {
				Type:        framework.TypeString,
				Description: "",
			},
			"key_type": {
				Type:        framework.TypeString,
				Description: "",
			},
			"bit_length": {
				Type:        framework.TypeString,
				Description: "",
			},
			"validity_in_days": {
				Type:        framework.TypeInt,
				Description: "",
			},
			"mail_address": {
				Type:        framework.TypeString,
				Description: "",
			},
			"postal_code": {
				Type:        framework.TypeString,
				Description: "",
			},
			"country": {
				Type:        framework.TypeString,
				Description: "",
			},
			"state": {
				Type:        framework.TypeString,
				Description: "",
			},
			"locality": {
				Type:        framework.TypeString,
				Description: "",
			},
			"street_address": {
				Type:        framework.TypeString,
				Description: "",
			},
			"organization_unit": {
				Type:        framework.TypeString,
				Description: "",
			},
			"organization": {
				Type:        framework.TypeString,
				Description: "",
			},
			"is_auto_renewal": {
				Type:        framework.TypeBool,
				Description: "",
			},
			"auto_regenerate_enabled": {
				Type:        framework.TypeBool,
				Description: "",
			},
			"encrypted_challenge_password": {
				Type:        framework.TypeString,
				Description: "",
			},
			"certificate_categories": {
				Type:        framework.TypeCommaStringSlice,
				Description: "",
			},
			"generic_fields": {
				Type:        framework.TypeKVPairs,
				Description: "",
			},
			"custom_attributes": {
				Type:        framework.TypeKVPairs,
				Description: "",
			},
			"certificate_groupName": {
				Type:        framework.TypeString,
				Description: "",
			},
			"user_defined_file_name": {
				Type:        framework.TypeString,
				Description: "",
			},
			"comments": {
				Type:        framework.TypeString,
				Description: "",
			},
			"file_name": {
				Type:        framework.TypeString,
				Description: "",
			},
			"attachment_file": {
				Type:        framework.TypeString,
				Description: "",
			},
			"file_ids": {
				Type:        framework.TypeStringSlice,
				Description: "",
			},
			"alt_names": {
				Type:        framework.TypeStringSlice,
				Description: "",
			},
			"category": {
				Type:        framework.TypeString,
				Description: "",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathReadCertSettingsAppViewX,
			logical.UpdateOperation: b.pathCreateCertSettingsAppViewX,
			logical.DeleteOperation: b.pathDeleteCertSettingsAppViewX,
		},
		HelpSynopsis:    "AppViewX - CertSettings",
		HelpDescription: "AppViewX - CertSettings",
	}
}

func (b *backend) pathReadCertSettingsAppViewX(context context.Context, request *logical.Request, data *framework.FieldData) (output *logical.Response, err error) {

	defer common.GlobalRecovery("pathReadCertSettingsAppViewX")

	certSettingsName := data.Get("name").(string)
	log.Println("Getting the CertSettings for the Name : ", certSettingsName)
	if certSettingsName == "" {
		return logical.ErrorResponse("Missing the CertSettings Name"), nil
	}

	certSettings, err := b.getCertSettings(context, request.Storage, certSettingsName)
	if err != nil {
		log.Println("Error in pathReadCertSettingsAppViewX : b.getCertSettings : ", err)
		return nil, err
	}

	if certSettings == nil {
		return nil, nil
	}
	output = &logical.Response{
		Data: certSettings.GenerateResponseData(),
	}
	return
}

func (b *backend) pathCreateCertSettingsAppViewX(context context.Context, request *logical.Request, data *framework.FieldData) (output *logical.Response, err error) {
	log.Println("Reached pathCreateCertSettingsAppViewX")

	defer common.GlobalRecovery("pathCreateCertSettingsAppViewX")

	certSettingsName := data.Get("name").(string)

	certSettings := &certSettings.CertSettings{
		File:                       data.Get("file").(string),
		HashFunction:               data.Get("hash_function").(string),
		KeyType:                    data.Get("key_type").(string),
		BitLength:                  data.Get("bit_length").(string),
		ValidityInDays:             data.Get("validity_in_days").(int),
		MailAddress:                data.Get("mail_address").(string),
		PostalCode:                 data.Get("postal_code").(string),
		Country:                    data.Get("country").(string),
		State:                      data.Get("state").(string),
		Locality:                   data.Get("locality").(string),
		StreetAddress:              data.Get("street_address").(string),
		OrganizationUnit:           data.Get("organization_unit").(string),
		Organization:               data.Get("organization").(string),
		IsAutoRenewal:              data.Get("is_auto_renewal").(bool),
		AutoRegenerateEnabled:      data.Get("auto_regenerate_enabled").(bool),
		EncryptedChallengePassword: data.Get("encrypted_challenge_password").(string),
		CertificateCategories:      data.Get("certificate_categories").([]string),
		GenericFields:              data.Get("generic_fields").(map[string]string),
		CustomAttributes:           data.Get("custom_attributes").(map[string]string),
		CertificateGroupName:       data.Get("certificate_groupName").(string),
		UserDefinedFileName:        data.Get("user_defined_file_name").(string),
		Comments:                   data.Get("comments").(string),
		FileName:                   data.Get("file_name").(string),
		AttachmentFile:             data.Get("attachment_file").(string),
		FileIds:                    data.Get("file_ids").([]string),
		AltNames:                   data.Get("alt_names").([]string),
		Category:                   data.Get("category").(string),
	}
	log.Println("************** length of certificate_categories : ", len(certSettings.CertificateCategories))
	certSettingsJson, err := logical.StorageEntryJSON("cert_settings/"+certSettingsName, certSettings)
	if err != nil {
		log.Println("Error in pathCreateCertSettingsAppViewX : logical.StorageEntryJSON : ", err)
		return nil, err
	}

	if err := request.Storage.Put(context, certSettingsJson); err != nil {
		log.Println("Error in pathCreateCertSettingsAppViewX : request.Storage.Put : ", err)
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathDeleteCertSettingsAppViewX(context context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	defer common.GlobalRecovery("pathDeleteCertSettingsAppViewX")

	err := request.Storage.Delete(context, "cert_settings/"+data.Get("name").(string))
	if err != nil {
		log.Println("Error in pathDeleteCertSettingsAppViewX : request.Storage.Delete : ", err)
		return nil, err
	}
	return nil, err
}

func (b *backend) getCertSettings(context context.Context, storage logical.Storage, name string) (output *certSettings.CertSettings, err error) {
	log.Println(" Path : ", "cert_settings/"+name)

	entry, err := storage.Get(context, "cert_settings/"+name)
	if err != nil {
		log.Println("Error while getting the certSettings ", entry)
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}
	var result certSettings.CertSettings
	if err := entry.DecodeJSON(&result); err != nil {
		log.Println("Error in getCertSettings : entry.DecodeJSON :", err)
		return nil, err
	}
	return &result, nil
}
