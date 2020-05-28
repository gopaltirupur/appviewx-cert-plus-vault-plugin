package ca

import "encoding/json"

type CA struct {
	CertificateAuthority  string            `json:"certificate_authority"`
	CaSettingName         string            `json:"ca_setting_name"`
	VendorSpecificDetails map[string]string `json:"vendor_specific_details"`
	DivisionId            string            `json:"division_id"`
	CertificateType       string            `json:"certificate_type"`
	ConnectorName         string            `json:"connector_name"`
	Description           string            `json:"description"`
}

func (config *CA) GenerateResponseData() map[string]interface{} {
	output := map[string]interface{}{}

	configMarshalled, _ := json.Marshal(config)

	json.Unmarshal(configMarshalled, &output)

	return output
}
