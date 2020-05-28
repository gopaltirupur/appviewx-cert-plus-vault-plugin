package certificateDownload

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
	CommonName   string `json:"commonName"`
	SerialNumber string `json:"serialNumber"`
	Format       string `json:"format"`
}

const (
	ACTION_ID = "certificate/download/format"
)

func (r Request) DownloadCertificate() (output []byte, err error) {

	baseURL := common.GetBaseURL(r.IsHTTPS, r.IP, r.Port, ACTION_ID, nil)

	headers := common.GetGeneralHeaders()
	headers["sessionId"] = r.SessionId

	response, err := common.MakePostRequest(baseURL, headers, r.Payload)
	if err != nil {
		log.Println("Error in Downloading the Certificate : ", err)
		return nil, err
	}
	output = response

	return
}
