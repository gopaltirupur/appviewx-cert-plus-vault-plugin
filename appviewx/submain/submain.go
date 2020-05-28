package submain

import (
	"appviewx-cert-plus-vault-plugin/appviewx/appConnector"
	"appviewx-cert-plus-vault-plugin/appviewx/ca"
	"appviewx-cert-plus-vault-plugin/appviewx/certSettings"
	"appviewx-cert-plus-vault-plugin/appviewx/certificate"
	"appviewx-cert-plus-vault-plugin/appviewx/certificateChain"
	"appviewx-cert-plus-vault-plugin/appviewx/certificateDownload"
	"appviewx-cert-plus-vault-plugin/appviewx/common"
	"appviewx-cert-plus-vault-plugin/appviewx/config"
	"appviewx-cert-plus-vault-plugin/appviewx/csr"
	"appviewx-cert-plus-vault-plugin/appviewx/session"
	"appviewx-cert-plus-vault-plugin/keygenerator"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
)

func MainPrivateKeyGeneration(certificate *certificate.CurrentCert, config *config.Config, ca *ca.CA, certSettings *certSettings.CertSettings) (csrContent, privateKey []byte, err error) {
	log.Println("Started : MainPrivateKeyGeneration")
	csrContent, privateKey, err = handleCSRAndPrivateKeyGenerationWithInplugin(certificate, config, ca, certSettings)
	if err != nil {
		log.Println("Error in handleCSRAndPrivateKeyGenerationWithInplugin : ", err)
		return
	}
	log.Println("End : MainPrivateKeyGeneration")
	return
}

func testMethod() {
	fmt.Println("testMethod")
}

func MainCertificateGeneration(csrContent []byte, certificate *certificate.CurrentCert, config *config.Config, ca *ca.CA, certSettings *certSettings.CertSettings) (certificateID string, err error) {
	return handleCertificateGeneration(csrContent, certificate, config, ca, certSettings)
}

func getDefaultValueIfNotAvailable(key, input string, map1 map[string]string) (output string) {
	if input == "" {
		output, _ = map1[key]
		return
	}
	output = input
	return
}

//TODO Mandatory Field Missing to be corrected
func handleCSRAndPrivateKeyGenerationWithInplugin(certificate *certificate.CurrentCert, config *config.Config, ca *ca.CA, certSettings *certSettings.CertSettings) (csrContent, privateKey []byte, err error) {
	log.Println("Started : handleCSRAndPrivateKeyGenerationWithInplugin")
	csrRequest := keygenerator.CSRRequest{
		CommonName:         certificate.CommonName,
		Country:            []string{certSettings.Country},
		Locality:           []string{certSettings.Locality},
		Organization:       []string{certSettings.Organization},
		OrganizationalUnit: []string{certSettings.OrganizationUnit},
		EmailAddress:       certSettings.MailAddress,
	}

	csrContent, privateKey, err = keygenerator.GetCSRAndPrivateKey(csrRequest, certificate, certSettings)
	if err != nil {
		log.Println("Error in keygenerator.GetCSRAndPrivateKey : ", err)
		return
	}

	log.Println("Finished : handleCSRAndPrivateKeyGenerationWithInplugin")
	return
}

func handleCertificateGeneration(csrContent []byte, currentCert *certificate.CurrentCert, config *config.Config, ca *ca.CA, certSettings *certSettings.CertSettings) (certificateID string, err error) {
	log.Println("starting session retrieval for config : ", config)
	sessionID, err := retrieveSession(config)
	if err != nil {
		log.Println("Error in Retrieving the Session ", err)
		return
	}
	log.Println("Successfully retrieved the session ", sessionID[5:9])

	log.Println("\nstarting upload CSR ")

	csrResponse, err := uploadCSR(string(csrContent), currentCert, config, ca, certSettings, sessionID)
	if err != nil {
		log.Println("Error in Uploading the CSR ", err)
		return
	}
	log.Println("Upload CSR Success : ", csrResponse)

	log.Println("Starting the Create Certificate")
	certResponse, err := createCertificate(csrResponse, currentCert, config, ca, certSettings, sessionID)
	if err != nil {
		log.Println("Error in createCertificate : ", err)
		return
	}
	responseData, err := json.Marshal(certResponse)
	if err != nil {
		log.Println("Error in Creating the Certificate ", err)
		return
	}
	log.Println("Create Certificate Response : ", string(responseData))
	log.Println("Finished the Create Certificate")

	return certResponse.ResponseInner.ResourceID, nil
}

func DownloadCertificateForCertificateID(certificateID string, config *config.Config) (isAllAvailable bool, finalSerialNumber string, certificateOutput []byte, uuid string, err error) {
	log.Println("Starting the chain Pool Loop ")

	finalCommonName := ""

	log.Println("************************* SLEEP - 120 SECONDS ******************************")
	// time.Sleep(120 * time.Second)
	log.Println("************************* WAKE UP ******************************")

	isAllAvailable = true

	log.Println("Starting the chain Pool ")
	chainResponse, err := getCertificateChain(certificateID, config)
	if err != nil {
		log.Println("Error in getCertificateChain : ", err)
		return
	}

	for _, certificateChain := range chainResponse.ResponseInner.CertificateChain {

		finalCommonName = certificateChain.CertificateView.CommonName
		finalSerialNumber = certificateChain.CertificateView.SerialNumber
		uuid = certificateChain.CertificateView.UUID

		if certificateChain.CertificateView.CommonName == "" || certificateChain.CertificateView.SerialNumber == "" {
			log.Println(" CommonName or SerialNumber not available ")
			isAllAvailable = false
			log.Println("Certificate Not Generated ")
			// time.Sleep(5 * time.Second)
			break
		}
	}
	log.Println("chainResponse : ", chainResponse)
	log.Println("Ending the chain Pool ")
	log.Println("Certificate Successfully Generated ... Exiting the chain Pool Loop")
	log.Println("finalCommonName : ", finalCommonName, " finalSerialNumber : ", finalSerialNumber)

	log.Println("")
	log.Println("Downloading the Certificate ")
	certificateOutput, err = downloadCertificate(finalCommonName, finalSerialNumber, config)
	if err != nil {
		log.Println("Error in downloadCertificate : ", err)
		return
	}

	log.Println("*************************** certificateOutput : ", string(certificateOutput))

	if json.Valid(certificateOutput) {
		//Setting empty array if the output is JSON ( due to error )
		certificateOutput = []byte{}
	}
	log.Println("Certificate Download Finished")
	return
}

func downloadCertificate(commonName, serialNumber string, config *config.Config) (output []byte, err error) {
	sessionID, err := retrieveSession(config)
	if err != nil {
		log.Println("Error in Retrieving the Session ", err)
		return
	}
	log.Println(" Successfully retrieved the session ", sessionID[5:9])

	payload := certificateDownload.Payload{commonName, serialNumber, "PEM"}

	request := certificateDownload.Request{payload, sessionID,
		config.IP, config.IsHTTPS, config.Port, config.UserName, config.Password}

	output, err = request.DownloadCertificate()
	if err != nil {
		log.Println("Error in Downloading the Certificate ", err)
		return
	}
	return
}

func getCertificateChain(resourceId string, config *config.Config) (output certificateChain.Response, err error) {
	sessionID, err := retrieveSession(config)
	if err != nil {
		log.Println("Error in Retrieving the Session ", err)
		return
	}
	log.Println("Successfully retrieved the session ", sessionID[5:9])

	request := certificateChain.Request{resourceId, sessionID, config.IP,
		config.IsHTTPS, config.Port, config.UserName, config.Password}

	output, err = request.GetCertificateHolisticViewChain()
	if err != nil {
		log.Println("Error in Retrieving the Certificate HolisticViewChain ", err)
		return
	}
	return
}

func createCertificate(csrResponse csr.Response, currentCert *certificate.CurrentCert, config *config.Config, ca *ca.CA, certSettings *certSettings.CertSettings, sessionID string) (output certificate.Response, err error) {

	payload := certificate.GeneratePayloadForCertificateCreate(currentCert, ca, certSettings)
	payload.CaConnectorInfo.ExistingUUID = csrResponse.Response.UUID

	certificateRequest := certificate.Request{payload, sessionID, config.IP,
		config.IsHTTPS, config.Port, config.UserName, config.Password}

	output, err = certificateRequest.CreateCertificate()
	if err != nil {
		log.Println("Error in Creating the Certificate ", err)
		return
	}
	return
}

func uploadCSR(csrContent string, currentCert *certificate.CurrentCert, config *config.Config, ca *ca.CA, certSettings *certSettings.CertSettings, sessionID string) (output csr.Response, err error) {

	csrRequest := csr.Request{csr.Payload{}, sessionID,
		config.IP, config.IsHTTPS, config.Port, config.UserName, config.Password}

	csrRequest.Payload.CSRContent = csrContent
	csrRequest.Payload.CertificateAuthority = ca.CertificateAuthority
	csrRequest.Payload.Category = certSettings.Category
	csrRequest.Payload.CommonName = currentCert.CommonName

	output, err = csrRequest.UploadCSR()
	if err != nil {
		log.Println("error in csrRequest.UploadCSR : ", err)
		return csr.Response{}, err
	}
	return
}

func retrieveSession(config *config.Config) (output string, err error) {

	sessionRequest := session.Request{}

	sessionRequest.IP = config.IP
	sessionRequest.Port = config.Port
	sessionRequest.IsHTTPS = config.IsHTTPS
	sessionRequest.UserName = config.UserName
	sessionRequest.Password = config.Password

	sessionResponse, err := sessionRequest.GetSession()
	if err != nil {
		fmt.Errorf("Error in getting the session", err)
		return "", err
	}

	response := sessionResponse["response"].(map[string]interface{})

	if response == nil || response["sessionId"] == nil || response["sessionId"] == "" {
		return "", errors.New("Empty Response or empty sessionId")
	}

	print(response["sessionId"].(string))
	output = response["sessionId"].(string)
	return
}

func print(input interface{}) (output []byte) {
	output, err := json.Marshal(input)
	if err != nil {
		fmt.Errorf("Error in Marshalling ", err)
	}
	return
}

func DefaultAppConnector(config *config.Config, uuid string) (err error) {
	sessionID, err := retrieveSession(config)
	if err != nil {
		log.Println("Error in Retrieving the Session ", err)
		return
	}
	log.Println("Successfully retrieved the session ", sessionID[5:9])
	payloadMap := appConnector.PayloadMap{getDeviceIP(), common.HASHICORP_VAULT, "Vault", uuid}
	payload := appConnector.Payload{payloadMap}

	request := appConnector.Request{payload, sessionID,
		config.IP, config.IsHTTPS, config.Port, config.UserName, config.Password}

	err = request.CreateAppConnector()
	if err != nil {
		log.Println("Error in Creating the app connector ", err)
		return
	}
	return
}

func getDeviceIP() (output string) {
	addressesFromInterface, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addressesFromInterface {
		if ipnetwork, ok := address.(*net.IPNet); ok && !ipnetwork.IP.IsLoopback() {
			if ipnetwork.IP.To4() != nil {
				return ipnetwork.IP.String()
			}
		}
	}
	return
}
