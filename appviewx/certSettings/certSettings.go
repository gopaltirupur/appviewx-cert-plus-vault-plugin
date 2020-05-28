package certSettings

import "encoding/json"

type CertSettings struct {
	File                       string            `json:"file"`
	HashFunction               string            `json:"hash_function"`
	KeyType                    string            `json:"key_type"`
	BitLength                  string            `json:"bit_length"`
	ValidityInDays             int               `json:"validity_in_days"`
	MailAddress                string            `json:"mail_address"`
	PostalCode                 string            `json:"postal_code"`
	Country                    string            `json:"country"`
	State                      string            `json:"state"`
	Locality                   string            `json:"locality"`
	StreetAddress              string            `json:"street_address"`
	OrganizationUnit           string            `json:"organization_unit"`
	Organization               string            `json:"organization"`
	IsAutoRenewal              bool              `json:"is_auto_renewal"`
	AutoRegenerateEnabled      bool              `json:"auto_regenerate_enabled"`
	EncryptedChallengePassword string            `json:"encrypted_challenge_password"`
	CertificateCategories      []string          `json:"certificate_categories"`
	GenericFields              map[string]string `json:"generic_fields"`
	CustomAttributes           map[string]string `json:"custom_attributes"`
	CertificateGroupName       string            `json:"certificate_groupName"`
	UserDefinedFileName        string            `json:"user_defined_file_name"`
	Comments                   string            `json:"comments"`
	FileName                   string            `json:"file_name"`
	AttachmentFile             string            `json:"attachment_file"`
	FileIds                    []string          `json:"file_ids"`
	AltNames                   []string          `json:"alt_names"`
	Category                   string            `json:"category"`
}

func (config *CertSettings) GenerateResponseData() map[string]interface{} {
	output := map[string]interface{}{}

	configMarshalled, _ := json.Marshal(config)

	json.Unmarshal(configMarshalled, &output)

	return output
}
