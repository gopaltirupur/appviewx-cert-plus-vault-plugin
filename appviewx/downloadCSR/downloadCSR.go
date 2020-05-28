package downloadCSR

import (
	"appviewx-cert-plus-vault-plugin/appviewx/common"
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
	UUID string `json:"uuId"`
	Log  bool   `json:"log"`
}

const (
	ACTION_ID = "cert-download-csr"
)

func (r Request) DownloadCSR() (output []byte, err error) {

	baseURL := common.GetBaseURL(r.IsHTTPS, r.IP, r.Port, ACTION_ID, nil)

	log.Println(baseURL)

	headers := common.GetGeneralHeaders()
	headers["sessionId"] = r.SessionId

	payloadMap := make(map[string]interface{})
	payloadMap["payload"] = r.Payload

	output, err = common.MakePostRequest(baseURL, headers, payloadMap)
	if err != nil {
		log.Println("Error in Downloading the CSR : ", err)
		return nil, err
	}
	return
}
