package createCSRAndKey

import (
	"appviewx-cert-plus-vault-plugin/appviewx/common"
	"encoding/json"
	"log"
)

type Request struct {
	Payload Payload

	SessionId string
	IP        string
	IsHTTPS   bool
	Port      string
	UserName  string
	Password  string
}

type Payload struct {
	CSRParameters         CSRParameters     `json:"csrParameters"`
	CertificateGroup      map[string]string `json:"certificateGroup"`
	CsrGenerationSource   string            `json:"csrGenerationSource"`
	CertificateHSMDetails []string          `json:"certificateHSMDetails"`
	FileIds               []string          `json:"fileIds"`
}

type CSRParameters struct {
	CommonName            string   `json:"commonName"`
	HashFunction          string   `json:"hashFunction"`
	KeyType               string   `json:"keyType"`
	BitLength             string   `json:"bitLength"`
	CertificateCategories []string `json:"certificateCategories"`
}

const (
	ACTION_ID = "cert-generate-csr-manual"
)

func (r Request) CreateCSRAndKey() (output string, err error) {

	baseURL := common.GetBaseURL(r.IsHTTPS, r.IP, r.Port, ACTION_ID, nil)

	log.Println(baseURL)

	headers := common.GetGeneralHeaders()
	headers["sessionId"] = r.SessionId

	payloadMap := make(map[string]interface{})
	payloadMap["payload"] = r.Payload

	response, err := common.MakePostRequest(baseURL, headers, payloadMap)
	if err != nil {
		log.Println("Error in Creating the CSR and Key : ", err)
		return "", err
	}
	log.Println(string(response))

	outputMap := map[string]string{}
	json.Unmarshal(response, &outputMap)
	output = outputMap["response"]

	return
}
