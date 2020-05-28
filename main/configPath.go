package main

import (
	"appviewx-cert-plus-vault-plugin/appviewx/common"
	"appviewx-cert-plus-vault-plugin/appviewx/config"
	"context"
	"log"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func getPathForConfigAppViewX(b backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: `Specifies the Name of the AppViewX Environment`,
			},
			"ip": {
				Type:        framework.TypeString,
				Description: `Specifies the IP of the AppViewX Environment`,
			},
			"port": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Specifies the Port of the AppViewX Environment`,
			},
			"is_https": &framework.FieldSchema{
				Type:        framework.TypeBool,
				Description: `Specifies whether the environment is https`,
			},
			"user_name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Specifies the UserName for the AppViewX Environment`,
			},
			"password": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Specifies the Password for the AppViewX Environment`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathReadConfigAppViewX,
			logical.UpdateOperation: b.pathCreateConfigAppViewX,
			logical.DeleteOperation: b.pathDeleteConfigAppViewX,
		},
		HelpSynopsis:    apviewxIssueCertificate,
		HelpDescription: apviewxIssueCertificate,
	}
}

func (b *backend) pathReadConfigAppViewX(ctx context.Context, req *logical.Request, data *framework.FieldData) (output *logical.Response, err error) {

	defer common.GlobalRecovery("pathReadConfigAppViewX")

	configName := data.Get("name").(string)
	log.Println("Getting Config for the Name :", configName)
	if configName == "" {
		return logical.ErrorResponse("Missing the Config Name"), nil
	}

	config, err := b.getConfig(ctx, req.Storage, configName)
	if err != nil {
		log.Println("Error in pathReadConfigAppViewX : b.getConfig", err)
		return nil, err
	}
	if config == nil {
		return nil, nil
	}
	output = &logical.Response{
		Data: config.GenerateResponseData(),
	}
	return
}

func (b *backend) pathCreateConfigAppViewX(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	defer common.GlobalRecovery("pathCreateConfigAppViewX")

	log.Println("Reached configCreateConfigAppViewX")

	configName := data.Get("name").(string)

	config := &config.Config{
		IP:       data.Get("ip").(string),
		Port:     data.Get("port").(string),
		IsHTTPS:  data.Get("is_https").(bool),
		UserName: data.Get("user_name").(string),
		Password: data.Get("password").(string),
	}

	configJson, err := logical.StorageEntryJSON("config/"+configName, config)
	if err != nil {
		log.Println("Error in pathCreateConfigAppViewX : logical.StorageEntryJSON ", err)
		return nil, err
	}

	if err := req.Storage.Put(ctx, configJson); err != nil {
		log.Println("Error in pathCreateConfigAppViewX : req.Storage.Put ", err)
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathDeleteConfigAppViewX(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	defer common.GlobalRecovery("pathDeleteConfigAppViewX")

	err := req.Storage.Delete(ctx, "config/"+data.Get("name").(string))
	if err != nil {
		log.Println("Error in pathDeleteConfigAppViewX : req.Storage.Delete")
		return nil, err
	}
	return nil, nil
}

func (b *backend) getConfig(ctx context.Context, s logical.Storage, name string) (output *config.Config, err error) {
	log.Println("Path : ", "config/"+name)

	entry, err := s.Get(ctx, "config/"+name)
	if err != nil {
		log.Println("Error while getting the config ", entry, err)
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var result config.Config
	if err := entry.DecodeJSON(&result); err != nil {
		log.Println("Error in getConfig : entry.DecodeJSON")
		return nil, err
	}
	return &result, nil
}
