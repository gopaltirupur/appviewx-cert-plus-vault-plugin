package certificate

import (
	"appviewx-cert-plus-vault-plugin/appviewx/ca"
	"appviewx-cert-plus-vault-plugin/appviewx/certSettings"
	"appviewx-cert-plus-vault-plugin/appviewx/common"
	"encoding/base64"
	"encoding/json"
	"log"
)

const (
	CSR_GENERATION_SOURCE = "uploadCSR"
)

type CurrentCert struct {
	CommonName                 string
	DNSNames                   []string
	IPAddresses                []string
	RFC822Names                []string
	DirectoryNames             []string
	RegisteredIDs              []string
	UniformResourceIdentifiers []string
	OtherNames                 []string
}

type Request struct {
	Payload   Payload
	SessionID string
	IP        string
	IsHTTPS   bool
	Port      string
	UserName  string
	Password  string
}

type Payload struct {
	CsrGenerationSource string           `json:"csrGenerationSource"`
	CaConnectorInfo     CaConnectorInfo  `json:"caConnectorInfo"`
	CertificateGroup    CertificateGroup `json:"certificateGroup"`
	FileIds             []string         `json:"fileIds"`
}

type CaConnectorInfo struct {
	ID                    string `json:"_id"`
	CertificateUUID       string `json:"certificateUuid"`
	ExistingUUID          string `json:"existingUuid"`
	CertificateAuthority  string `json:"certificateAuthority"`
	IsAutoRenewal         bool   `json:"isAutoRenewal"`
	AutoRegenerateEnabled bool   `json:"autoRegenerateEnabled"`
	CaSettingName         string `json:"caSettingName"`
	DivisionId            string `json:"divisionId"`
	// CertificateProfileName string                `json:"certificateProfileName"`
	CertificateType       string            `json:"certificateType"`
	Name                  string            `json:"name"`
	Description           string            `json:"description"`
	File                  string            `json:"file"`
	GenericFields         map[string]string `json:"genericFields"`
	CsrParameters         CsrParameters     `json:"csrParameters"`
	CertAttachments       CertAttachments   `json:"certAttachments"`
	ValidityInDays        int               `json:"validityInDays"`
	VendorSpecificDetails map[string]string `json:"vendorSpecificDetails"`
	CustomAttributes      map[string]string `json:"customAttributes"`
}

type CertAttachments struct {
	UserDefinedFileName string `json:"UserDefinedFileName"`
	Comments            string `json:"Comments"`
	FileName            string `json:"fileName"`
	AttachmentFile      string `json:"attachmentFile"`
}

type CsrParameters struct {
	CommonName                 string           `json:"commonName"`
	SubjectAlternativeNames    []string         `json:"subjectAlternativeNames"`
	Organization               string           `json:"organization"`
	OrganizationUnit           string           `json:"organizationUnit"`
	StreetAddress              string           `json:"streetAddress"`
	Locality                   string           `json:"locality"`
	State                      string           `json:"state"`
	Country                    string           `json:"country"`
	PostalCode                 string           `json:"postalCode"`
	MailAddress                string           `json:"mailAddress"`
	EncryptedChallengePassword string           `json:"encryptedChallengePassword"`
	HashFunction               string           `json:"hashFunction"`
	KeyType                    string           `json:"keyType"`
	BitLength                  string           `json:"bitLength"`
	CertificateCategories      []string         `json:"certificateCategories"`
	EnhancedSANTypes           EnhancedSANTypes `json:"enhancedSANTypes"`
}

type EnhancedSANTypes struct {
	DNSNames                   []string `json:"dNSNames"`
	IPAddresses                []string `json:"iPAddresses"`
	RFC822Names                []string `json:"rfc822Names"`
	DirectoryNames             []string `json:"directoryNames"`
	RegisteredIDs              []string `json:"registeredIDs"`
	UniformResourceIdentifiers []string `json:"uniformResourceIdentifiers"`
	OtherNames                 []string `json:"otherNames"`
}

type CertificateGroup struct {
	Name string `json:"name"`
}

type Response struct {
	ResponseInner ResponseInner     `json:"response"`
	Message       string            `json:"message"`
	AppStatusCode string            `json:"appStatusCode"`
	Tags          map[string]string `json:"tags"`
	Headers       string            `json:"headers"`
}

type ResponseInner struct {
	ResourceID string `json:"resourceId"`
	RequestID  string `json:"requstId"`
}

const (
	ACTION_ID = "certificate/create"
)

func (r Request) CreateCertificate() (output Response, err error) {

	baseURL := common.GetBaseURL(r.IsHTTPS, r.IP, r.Port, ACTION_ID, nil)

	headers := common.GetGeneralHeaders()
	headers["sessionId"] = r.SessionID

	response, err := common.MakePostRequest(baseURL, headers, r.Payload)
	if err != nil {
		log.Println("Error in Creating the Certificate ", err)
		return Response{}, err
	}

	output = Response{}
	err1 := json.Unmarshal(response, &output)
	if err1 != nil {
		log.Println("error in Unmarshal ")
		return Response{}, err1
	}
	return
}

func GeneratePayloadForCertificateCreate(currentCert *CurrentCert, ca *ca.CA, certSettings *certSettings.CertSettings) (payload Payload) {
	payload = Payload{}

	payload.CsrGenerationSource = CSR_GENERATION_SOURCE
	payload.CaConnectorInfo = getCAConnectorInfo(currentCert, ca, certSettings)
	payload.CertificateGroup = CertificateGroup{certSettings.CertificateGroupName}
	payload.FileIds = certSettings.FileIds
	return
}

func getCAConnectorInfo(currentCert *CurrentCert, ca *ca.CA, certSettings *certSettings.CertSettings) (output CaConnectorInfo) {
	output = CaConnectorInfo{}
	output.CertificateAuthority = ca.CertificateAuthority
	output.IsAutoRenewal = certSettings.IsAutoRenewal
	output.AutoRegenerateEnabled = certSettings.AutoRegenerateEnabled
	output.CaSettingName = ca.CaSettingName
	output.DivisionId = ca.DivisionId
	output.CertificateType = ca.CertificateType
	output.Name = ca.ConnectorName
	output.Description = ca.Description
	output.File = certSettings.File
	output.ValidityInDays = certSettings.ValidityInDays

	output.CsrParameters = getCSRParameters(currentCert, ca, certSettings)
	output.CertAttachments = getCertAttachments(currentCert, ca, certSettings)
	output.GenericFields = certSettings.GenericFields
	output.VendorSpecificDetails = ca.VendorSpecificDetails
	output.CustomAttributes = certSettings.CustomAttributes
	return
}

func getCertAttachments(currentCert *CurrentCert, ca *ca.CA, certSettings *certSettings.CertSettings) (output CertAttachments) {
	output = CertAttachments{}
	output.UserDefinedFileName = certSettings.UserDefinedFileName
	output.Comments = certSettings.Comments
	output.FileName = certSettings.FileName
	output.AttachmentFile = certSettings.AttachmentFile
	return
}

func getCSRParameters(currentCert *CurrentCert, ca *ca.CA, certSettings *certSettings.CertSettings) (output CsrParameters) {
	output = CsrParameters{}

	output.CommonName = currentCert.CommonName
	output.SubjectAlternativeNames = certSettings.AltNames
	output.Organization = certSettings.Organization
	output.OrganizationUnit = certSettings.OrganizationUnit
	output.StreetAddress = certSettings.StreetAddress
	output.Locality = certSettings.Locality
	output.State = certSettings.State
	output.Country = certSettings.Country
	output.PostalCode = certSettings.PostalCode
	output.MailAddress = certSettings.MailAddress
	output.EncryptedChallengePassword = base64.StdEncoding.EncodeToString([]byte(certSettings.EncryptedChallengePassword))
	output.HashFunction = certSettings.HashFunction
	output.KeyType = certSettings.KeyType
	output.BitLength = certSettings.BitLength
	output.CertificateCategories = certSettings.CertificateCategories
	output.EnhancedSANTypes = getEnhancedSANTypes(currentCert, ca, certSettings)

	return
}

func getEnhancedSANTypes(currentCert *CurrentCert, ca *ca.CA, certSettings *certSettings.CertSettings) (output EnhancedSANTypes) {
	output = EnhancedSANTypes{}
	output.DNSNames = currentCert.DNSNames
	output.IPAddresses = currentCert.IPAddresses
	output.RFC822Names = currentCert.RFC822Names
	output.DirectoryNames = currentCert.DirectoryNames
	output.RegisteredIDs = currentCert.RegisteredIDs
	output.UniformResourceIdentifiers = currentCert.UniformResourceIdentifiers
	output.OtherNames = currentCert.OtherNames
	return
}
