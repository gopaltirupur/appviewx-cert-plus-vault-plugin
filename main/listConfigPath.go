package main

import (
	"appviewx-cert-plus-vault-plugin/appviewx/common"
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

//This path is to get the list of configs availabel in the vault
func getPathForListConfigs(backend backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: backend.pathConfigList,
		},
		HelpSynopsis:    "Listing Config Paths",
		HelpDescription: "Listing Config Paths",
	}
}

func (b *backend) pathConfigList(context context.Context, request *logical.Request, data *framework.FieldData) (response *logical.Response, err error) {

	defer common.GlobalRecovery("pathConfigList")

	pathList, err := request.Storage.List(context, "config/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(pathList), nil
}
