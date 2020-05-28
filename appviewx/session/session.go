package session

import (
	"appviewx-cert-plus-vault-plugin/appviewx/common"
	"encoding/json"
	"log"
)

//Request to get the session
type Request struct {
	IP       string
	IsHTTPS  bool
	Port     string
	UserName string
	Password string
}

const (
	ACTION_ID = "acctmgmt-perform-login"
)

func (r Request) GetSession() (output map[string]interface{}, err error) {
	// output = make(map[string]interface{})
	baseURL := common.GetBaseURL(r.IsHTTPS, r.IP, r.Port, ACTION_ID, nil)

	headers := common.GetGeneralHeaders()
	headers["username"] = r.UserName
	headers["password"] = r.Password

	response, err := common.MakePostRequest(baseURL, headers, make(map[string]string))
	if err != nil {
		log.Println("Error in making post request at GetSession :", err)
		return nil, err
	}

	var decoded map[string]interface{}
	err1 := json.Unmarshal(response, &decoded)
	if err1 != nil {
		log.Println("Error in Unmarshalling at GetSession :", err1)
		return nil, err1
	}

	log.Println(decoded)

	output = decoded

	log.Println("")
	return
}
