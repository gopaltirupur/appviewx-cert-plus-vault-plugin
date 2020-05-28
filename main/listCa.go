package main

import (
	"appviewx-cert-plus-vault-plugin/appviewx/common"
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

//This path is to get the list of CA configs available in the vault
func getPathForListCa(backend backend) *framework.Path {
	return &framework.Path{
		Pattern: "ca/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: backend.pathCaList,
		},
		HelpSynopsis:    "Listing CA Paths",
		HelpDescription: "Listing CA Paths",
	}
}

func (b *backend) pathCaList(context context.Context, request *logical.Request, data *framework.FieldData) (response *logical.Response, err error) {

	defer common.GlobalRecovery("pathCaList")

	caList, err := request.Storage.List(context, "ca/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(caList), nil
}
