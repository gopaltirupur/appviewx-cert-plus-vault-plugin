package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
)

var apviewxIssueCertificate string = `AppViewX - Issue Certificate`

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		log.Fatalf("error in parsing the command line arguments ", os.Args, err)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		log.Fatal(err)
	}

}

func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
	storage     logical.Storage
	crlLifeTime time.Duration
}

type ForStorageCertificate struct {
	CommonName    string   `json:"common_name"`
	AltNames      []string `json:"alt_names"`
	Certificate   string   `json:"certificate"`
	PrivateKey    string   `json:"private_key"`
	CSR           string   `json:"csr"`
	CertificateID string   `json:"certificate_id"`
	Status        bool     `json:"status"`
	SerialNumber  string   `json:"serial_number"`
}

func Backend(c *logical.BackendConfig) *backend {
	var b backend

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			// Unauthenticated: []string{"issue"},
			SealWrapStorage: []string{
				"roles/",
			},
		},
		Secrets: []*framework.Secret{
			avxsecrets(&b),
		},
		Paths: []*framework.Path{
			getPathForIssueCertificateFromViaAppViewX(b),
			getPathForCertReadFromVault(b),
			getPathForConfigAppViewX(b),
			getPathForListConfigs(b),
			getPathForListCerts(b),
			getPathForDiscoveryOfCertificatesFromVault(b),
			getPathForCaAppViewX(b),
			getPathForListCa(b),
			getPathForCertSettingsAppViewX(b),
			getPathForListCertSettings(b),
		},
	}
	b.storage = c.StorageView
	b.crlLifeTime = time.Hour * 72

	return &b
}

func avxsecrets(b *backend) *framework.Secret {
	certsTypes := "pki"
	return &framework.Secret{
		Type: certsTypes,
		Fields: map[string]*framework.FieldSchema{
			"certificate": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: ``,
			},
			"private-key": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: ``,
			},
			"csr": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: ``,
			},
			"serial": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: ``,
			},
		},
	}
}

func getValutForKeyFromDataString(data *framework.FieldData, key string) (output string) {
	if data.Get(key) != nil {
		output = data.Get(key).(string)
	}
	return
}

func getValutForKeyFromDataStringSlice(data *framework.FieldData, key string) (output []string) {
	if data.Get(key) != nil {
		output = data.Get(key).([]string)
	}
	return
}

func displayRoles(data *framework.FieldData, ctx context.Context, req *logical.Request) {
	roles := data.Get("role").(string)

	entry, err := req.Storage.Get(ctx, "role/"+roles)
	if err != nil {
		log.Println("Error in obtaining the role")
	}
	entryOutput, err := json.Marshal(entry)
	if err != nil {
		log.Println("Error in Marshalling ")
	}
	log.Println("entryOutput :", string(entryOutput))
}
