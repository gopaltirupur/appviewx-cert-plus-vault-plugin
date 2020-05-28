package csr

import (
	"appviewx-cert-plus-vault-plugin/appviewx/common"
	"encoding/json"
	"log"
)

type Request struct {
	Payload   Payload `json:"payload"`
	SessionID string
	IP        string
	IsHTTPS   bool
	Port      string
	UserName  string
	Password  string
}

type Payload struct {
	CSRContent           string `json:"csrContent"`
	CertificateAuthority string `json:"certificateAuthority"`
	Category             string `json:"category"`
	CommonName           string `json:"commonName"`
}

type Response struct {
	Response ResponseInner `json:"response"`
}

type ResponseInner struct {
	UUID      string    `json:"uuid"`
	CSRParams CSRParams `json:"csrParams"`
}

type CSRParams struct {
	CommonName   string `json:"commonName"`
	KeyType      string `json:"keyType"`
	BitLength    string `json:"bitLength"`
	HashFunction string `json:"hashFunction"`
}

const (
	ACTION_ID = "cert-csr-upload"
)

func (r Request) UploadCSR() (output Response, err error) {

	baseURL := common.GetBaseURL(r.IsHTTPS, r.IP, r.Port, ACTION_ID, nil)

	payloadMap := make(map[string]interface{})
	payloadMap["payload"] = r.Payload

	// baseURL :=
	log.Println(baseURL)

	headers := common.GetGeneralHeaders()
	headers["sessionId"] = r.SessionID

	response, err := common.MakePostRequest(baseURL, headers, payloadMap)
	if err != nil {
		log.Println("Error in submitting the CSr ", err)
		return Response{}, err
	}

	log.Println(string(response))

	output = Response{}
	err1 := json.Unmarshal(response, &output)
	if err1 != nil {
		log.Println("Error in unmarshal ")
		return Response{}, err1
	}

	return
}
