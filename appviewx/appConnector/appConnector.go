package appConnector

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
	Payload PayloadMap `json:"payload"`
}

type PayloadMap struct {
	DeviceName string `json:"deviceName"`
	Vendor     string `json:"vendor"`
	Category   string `json:"category"`
	Uuid       string `json:"uuid"`
}

const (
	ACTION_ID = "cert-default-application-connector-save"
)

func (r Request) CreateAppConnector() (err error) {
	baseURL := common.GetBaseURL(r.IsHTTPS, r.IP, r.Port, ACTION_ID, nil)

	headers := common.GetGeneralHeaders()
	headers["sessionId"] = r.SessionId

	_, err = common.MakePostRequest(baseURL, headers, r.Payload)
	if err != nil {
		log.Println("Error in Creating the App Connector : ", err)
		return
	}
	return
}
