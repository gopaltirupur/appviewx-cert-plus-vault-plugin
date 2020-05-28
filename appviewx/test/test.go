package test

import (
	"appviewx-cert-plus-vault-plugin/appviewx/config"
	"appviewx-cert-plus-vault-plugin/appviewx/session"
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
)

func Test() {
	log.Println("***********  ++++++++++++++++++++++ ******************")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	log.Println(tr)
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("GET", "https://www.google.co.in", nil)
	// req := n
	resp, err := client.Do(req)
	log.Println(err)
	output, err := ioutil.ReadAll(resp.Body)

	log.Println("Request Output : ", string(output))
	log.Println()
}

func RetrieveSession() (output string, err error) {

	sessionRequest := session.Request{}
	log.Println(sessionRequest)

	sessionRequest.IP = config.Config.IP
	sessionRequest.Port = config.Config.Port
	sessionRequest.IsHTTPS = config.Config.IsHttps
	sessionRequest.UserName = config.Config.UserName
	sessionRequest.Password = config.Config.Password

	var sessionResponse map[string]interface{}
	// sessionResponse, err = sessionRequest.GetSession()
	if err != nil {
		log.Println("Error in getting the session")
		return "", err
	}

	response := sessionResponse["response"].(map[string]interface{})
	log.Println(response["sessionId"].(string))
	output = response["sessionId"].(string)
	return
}
