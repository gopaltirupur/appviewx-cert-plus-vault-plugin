package certificateChain

import (
	"appviewx-cert-plus-vault-plugin/appviewx/common"
	"encoding/json"
	"log"
)

type Response struct {
	ResponseInner ResponseInner     `json:"response"`
	Message       string            `json:"message"`
	AppStatusCode string            `json:"appStatusCode"`
	Tags          map[string]string `json:"tags"`
	Headers       string            `json:"headers"`
}

type ResponseInner struct {
	CertificateChain []CertificateChain `json:"certificateChain"`
}
type CertificateChain struct {
	CertificateView CertificateView `json:"certificateView"`
}

type CertificateView struct {
	CommonName       string `json:"commonName"`
	SerialNumber     string `json:"serialNumber"`
	issuerCommonName string `json:"issuerCommonName"`
	UUID             string `json:"uuid"`
}

const (
	ACTION_ID = "cert-holisticview-get-chain-with-actions"
)

type Request struct {
	CertificateID string
	SessionID     string
	IP            string
	IsHTTPS       bool
	Port          string
	UserName      string
	Password      string
}

func (r Request) GetCertificateHolisticViewChain() (output Response, err error) {

	paramMap := make(map[string]string)
	paramMap["certificateId"] = r.CertificateID

	baseURL := common.GetBaseURL(r.IsHTTPS, r.IP, r.Port, ACTION_ID, paramMap)

	headers := common.GetGeneralHeaders()
	headers["sessionId"] = r.SessionID

	response, err := common.MakeGetRequest(baseURL, headers)
	if err != nil {
		log.Println("Error in getting the Certificate Chain ", err)
		return Response{}, nil
	}

	output = Response{}
	err1 := json.Unmarshal(response, &output)
	if err1 != nil {
		log.Println("Error in UnMarshal")
		return Response{}, err1
	}
	return
}
