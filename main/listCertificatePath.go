package main

import (
	"appviewx-cert-plus-vault-plugin/appviewx/common"
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

//This path is to list the available certificates in the vault ( created by this plugin )
func getPathForListCerts(backend backend) *framework.Path {
	return &framework.Path{
		Pattern: "certs/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: backend.pathCertsList,
		},
		HelpSynopsis:    "Listing Config Paths",
		HelpDescription: "Listing Config Paths",
	}
}

func (b *backend) pathCertsList(context context.Context, request *logical.Request, data *framework.FieldData) (response *logical.Response, err error) {

	defer common.GlobalRecovery("pathCertsList")

	pathList, err := request.Storage.List(context, "certs/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(pathList), nil
}
