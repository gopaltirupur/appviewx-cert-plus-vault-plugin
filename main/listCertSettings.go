package main

import (
	"appviewx-cert-plus-vault-plugin/appviewx/common"
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

//This path is to get the list of CA configs available in the vault
func getPathForListCertSettings(backend backend) *framework.Path {
	return &framework.Path{
		Pattern: "cert_settings/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: backend.pathCertSettingsList,
		},
		HelpSynopsis:    "Listing Cert Settings Paths",
		HelpDescription: "Listing Cert Settings Paths",
	}
}

func (b *backend) pathCertSettingsList(context context.Context, request *logical.Request, data *framework.FieldData) (response *logical.Response, err error) {

	defer common.GlobalRecovery("pathCertSettingsList")

	caList, err := request.Storage.List(context, "cert_settings/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(caList), nil
}
