package common

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
)

const (
	PARAM_BASE      = "?gwkey=f000ca01&gwsource=WEB"
	HASHICORP_VAULT = "Hashicorp Vault"
)

func MakePostRequest(url string, headers map[string]string, body interface{}) (output []byte, err error) {

	bodyContent, err := json.Marshal(body)
	if err != nil {
		log.Println("Error while Marshalling")
		return nil, err
	}

	log.Println("----------------------------------------------------------")
	log.Println("Request Details : ")
	log.Println("URL : ", url)
	// log.Println("Headers :", headers)
	log.Println("Body : ", string(bodyContent))

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyContent))
	if err != nil {
		log.Println("Error in creating new request :", err)
		return nil, err
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error in getting response from the server :", err)
		return nil, err
	}

	output, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error in reading response from the body :", err)
		return nil, err
	}
	defer resp.Body.Close()

	return
}

func MakeGetRequest(url string, headers map[string]string) (output []byte, err error) {

	log.Println("----------------------------------------------------------")
	log.Println("Request Details : ")
	log.Println("URL : ", url)
	log.Println("Headers :", headers)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Println("Error in creating a new request :", err)
		return nil, err
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error in getting response from the server :", err)
		return nil, err
	}

	output, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error in reading contents from the response :", err)
		return nil, err
	}

	log.Println("Request Output : ", string(output))
	log.Println()

	defer resp.Body.Close()
	return
}

func GetBaseURL(isHttps bool, ip, port, actionID string, paramMap map[string]string) (output string) {
	var urlBuffer bytes.Buffer

	if isHttps {
		urlBuffer.WriteString("https://")
	} else {
		urlBuffer.WriteString("http://")
	}
	urlBuffer.WriteString(ip)
	urlBuffer.WriteString(":")
	urlBuffer.WriteString(port)
	urlBuffer.WriteString("/")
	urlBuffer.WriteString("avxapi/")
	urlBuffer.WriteString(actionID)
	urlBuffer.WriteString(getParamPathString(paramMap))
	output = urlBuffer.String()
	return
}

func getParamPathString(paramMap map[string]string) (output string) {
	output = PARAM_BASE
	for k, v := range paramMap {
		output = output + "&" + k + "=" + v
	}
	return output
}

func GetGeneralHeaders() map[string]string {
	output := make(map[string]string)

	output["Content-Type"] = "application/json"
	output["Accept"] = "application/json"

	return output
}

func GetMapForString(input string) (output map[string]string) {
	output = make(map[string]string)
	json.Unmarshal([]byte(input), &output)
	return output
}

func GlobalRecovery(message string) {
	if r := recover(); r != nil {
		log.Println("*********** RECOVERY ************** :", message, r)
	}
}
