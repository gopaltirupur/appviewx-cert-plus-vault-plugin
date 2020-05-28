package keygenerator

import (
	"appviewx-cert-plus-vault-plugin/appviewx/certSettings"
	"appviewx-cert-plus-vault-plugin/appviewx/certificate"
	"bufio"
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type CSRRequest struct {
	CommonName         string
	Country            []string
	Province           []string
	Locality           []string
	Organization       []string
	OrganizationalUnit []string
	EmailAddress       string
}

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
var dnsNames = asn1.ObjectIdentifier{2, 5, 29, 17, 7, 2}

func GetCSRAndPrivateKey(csrRequest CSRRequest, certificate *certificate.CurrentCert, certSettings *certSettings.CertSettings) (csrContent, privateKey []byte, err error) {
	log.Println("Started : GetCSRAndPrivateKey")
	subj := pkix.Name{
		CommonName:         csrRequest.CommonName,
		Country:            csrRequest.Country,
		Province:           csrRequest.Province,
		Locality:           csrRequest.Locality,
		Organization:       csrRequest.Organization,
		OrganizationalUnit: csrRequest.OrganizationalUnit,
	}
	bits, err := strconv.Atoi(certSettings.BitLength)
	if err != nil {
		log.Println("Error while converting BigLength to int ", certSettings.BitLength, err)
		return
	}
	if strings.ToLower(certSettings.KeyType) == "rsa" {
		privateKey, csrContent, err = genCSRForRSA(subj, csrRequest.EmailAddress, bits, certificate, certSettings)
	} else if strings.ToLower(certSettings.KeyType) == "ecdsa" {
		privateKey, csrContent, err = genCSRForECDSA(subj, csrRequest.EmailAddress, bits, certificate, certSettings)
	} else if strings.ToLower(certSettings.KeyType) == "dsa" {
		privateKey, csrContent, err = genCSRForDSA(subj, csrRequest.EmailAddress, bits, certificate, certSettings)
	}

	if err != nil {
		log.Println("Error in genCSR : ", err)
		return
	}
	log.Println("Finished : GetCSRAndPrivateKey")
	return
}

func genCSRForDSA(subj pkix.Name, email string, bits int, certificate *certificate.CurrentCert, certSettings *certSettings.CertSettings) (pemKey, csr []byte, err error) {
	log.Println("Started : getCSRForDSA")

	params := new(dsa.Parameters)

	dsaParameterSize, err := getParameterSizeBasedOnBitLength(bits)
	if err != nil {
		log.Println("Given bit : ", bits, " not supported in dsa ", err)
		return nil, nil, err
	}

	if err := dsa.GenerateParameters(params, rand.Reader, dsaParameterSize); err != nil {
		log.Println("Error in dsa.GenerateParameters : ", err)
		return nil, nil, err
	}
	privateKey := new(dsa.PrivateKey)
	var b bytes.Buffer
	foo := bufio.NewWriter(&b)

	privateKeyEncoder := gob.NewEncoder(foo)
	err = privateKeyEncoder.Encode(privateKey)
	byPrivatekey := b.Bytes()

	keyBytes := byPrivatekey
	if err != nil {
		log.Println("Error in Marshalling DSA private key : ", err)
		return nil, nil, err
	}
	log.Println("******************* Private Marshal success *********************")

	privateKey.PublicKey.Parameters = *params
	dsa.GenerateKey(privateKey, rand.Reader)
	var publicKey dsa.PublicKey = privateKey.PublicKey

	var b1 bytes.Buffer
	foo1 := bufio.NewWriter(&b1)

	publicKeyEncoder := gob.NewEncoder(foo1)
	err = publicKeyEncoder.Encode(publicKey)
	byPublicKey := b1.Bytes()

	pubkeyBytes := byPublicKey
	if err != nil {
		log.Println("Error in Marshalling the DSA private key ", err)
		return nil, nil, err
	}

	pemPubKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubkeyBytes}))
	pemKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	log.Println(pemPubKey)

	rawSubj := subj.ToRDNSequence()
	if len(email) > 0 {
		rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
			{Type: oidEmailAddress, Value: email},
			// {Type: dnsNames, Value: "DNS1"},
		})
	}
	asn1Subj, err := asn1.Marshal(rawSubj)
	if err != nil {
		log.Println("Error in asn1.Marshal : ", err)
		return
	}
	template := x509.CertificateRequest{
		RawSubject: asn1Subj,
	}
	setDataFromCurrentCertificate(&template, certificate)

	err = setHashFunctionDSA(&template, certSettings)
	if err != nil {
		log.Println("Error in getting the hashFunction for DSA : ", err)
		return
	}
	dsaPrivateKey := DsaPrivateKey{DsaPrivateKey: *privateKey}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, &dsaPrivateKey)

	if err != nil {
		log.Println("Error in x509.CrateCertificateRequest : * - ", err)
		return
	}
	csr = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	log.Println("Finished : genCSRForDSA")

	return
}

type DsaPrivateKey struct {
	DsaPrivateKey dsa.PrivateKey
}

func (priv *DsaPrivateKey) Public() crypto.PublicKey {
	return &priv.DsaPrivateKey.PublicKey
}

func (priv *DsaPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := dsa.Sign(rand, &priv.DsaPrivateKey, digest)
	if err != nil {
		log.Println("Error in Signing ")
		return nil, err
	}
	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)
	return signature, nil
}

func setHashFunctionDSA(template *x509.CertificateRequest, certSettings *certSettings.CertSettings) (err error) {
	hashRequired := strings.ToLower(certSettings.HashFunction)
	switch hashRequired {

	case "sha160":
		template.SignatureAlgorithm = x509.DSAWithSHA1
	case "sha256":
		template.SignatureAlgorithm = x509.DSAWithSHA256
	default:
		return errors.New("Error in setHashFunctionDSA - only sha160 and sha256 hashfunctions are supported for DSA ")
	}
	return nil
}

func getParameterSizeBasedOnBitLength(bits int) (output dsa.ParameterSizes, err error) {
	switch bits {
	case 1024:
		output = dsa.L1024N160
	case 2048:
		output = dsa.L2048N256
	default:
		return 0, errors.New("Given Bit Length not supported for DSA : " + strconv.Itoa(bits))
	}
	return
}

func getElliptic(bits int) (output elliptic.Curve, err error) {
	switch bits {
	case 224:
		output = elliptic.P224()
	case 256:
		output = elliptic.P256()
	case 384:
		output = elliptic.P384()
	default:
		err = errors.New("Given bits does not contain Elliptic curve : " + strconv.Itoa(bits))
	}
	return
}

func genCSRForECDSA(subj pkix.Name, email string, bits int, certificate *certificate.CurrentCert, certSettings *certSettings.CertSettings) (pemKey, csr []byte, err error) {
	log.Println("Started : genCSRForDSA")

	ellipticCurve, err := getElliptic(bits)
	if err != nil {
		log.Println("Given Elliptic Curve bits not supported : ", bits)
		return nil, nil, err
	}
	privateKey, err := ecdsa.GenerateKey(ellipticCurve, rand.Reader)

	if err != nil {
		log.Println("Error in dsa.GenerateKey : ", err)
		return nil, nil, err
	}

	var b bytes.Buffer
	foo := bufio.NewWriter(&b)

	privateKeyEncoder := gob.NewEncoder(foo)
	privateKeyEncoder.Encode(privateKey)
	byPrivatekey := b.Bytes()

	keyBytes, err := byPrivatekey, nil
	if err != nil {
		log.Println("Error in Marshalling ECDSA private key : ", err)
		return nil, nil, err
	}
	log.Println("*************** Private Marshal success *****************")

	var pubkey ecdsa.PublicKey
	pubkey = privateKey.PublicKey

	var b1 bytes.Buffer
	foo1 := bufio.NewWriter(&b1)

	publicKeyEncoder := gob.NewEncoder(foo1)
	publicKeyEncoder.Encode(pubkey)
	byPublickey := b1.Bytes()

	// pubkeyBytes, err := asn1.Marshal(pubkey)
	pubkeyBytes, err := byPublickey, nil
	if err != nil {
		log.Println("Error in Marshalling the ECDSA public key : ", err)
		return nil, nil, err
	}

	pemPubKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubkeyBytes}))
	pemKey = pem.EncodeToMemory((&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
	log.Println(pemPubKey)

	rawSubj := subj.ToRDNSequence()
	if len(email) > 0 {
		rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
			{Type: oidEmailAddress, Value: email},
			// {Type: dnsNames, Value: "DNS1"},
		})
	}

	asn1Subj, err := asn1.Marshal(rawSubj)
	if err != nil {
		log.Println("Error in asn1.Marshal :", err)
		return
	}
	template := x509.CertificateRequest{
		RawSubject: asn1Subj,
	}
	setDataFromCurrentCertificate(&template, certificate)

	err = setHashFunctionECDSA(&template, certSettings)
	if err != nil {
		log.Println("Error in getting the hashFunction for DSA : ", err)
		return
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	// csx509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		log.Println("Error in x509.CreateCertificateRequest : ", err)
		return
	}
	csr = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	log.Println("Finished : genCSRForECDSA")

	return
}

func setHashFunctionECDSA(template *x509.CertificateRequest, certSettings *certSettings.CertSettings) (err error) {
	hashRequired := strings.ToLower(certSettings.HashFunction)
	switch hashRequired {
	case "sha160":
		template.SignatureAlgorithm = x509.ECDSAWithSHA1
	case "sha256":
		template.SignatureAlgorithm = x509.ECDSAWithSHA256
	case "sha384":
		template.SignatureAlgorithm = x509.ECDSAWithSHA384
	case "sha512":
		template.SignatureAlgorithm = x509.ECDSAWithSHA512
	default:
		return errors.New("Given hash function : " + certSettings.HashFunction + " Not supported")
	}
	return nil
}

//TODO: - HashFunction, keyType, Validation, Enhanced SAN Type to be handled
func genCSRForRSA(subj pkix.Name, email string, bits int, certificate *certificate.CurrentCert, certSettings *certSettings.CertSettings) (pemKey, csr []byte, err error) {
	log.Println("Started : genCSRForRSA")
	keyBytes, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Println("rsa.GenerateKey : ", err)
		return
	}

	pemPubKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&keyBytes.PublicKey)}))
	pemKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(keyBytes)})
	log.Println(pemPubKey)

	rawSubj := subj.ToRDNSequence()
	if len(email) > 0 {
		rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
			{Type: oidEmailAddress, Value: email},
			// {Type: dnsNames, Value: "DNS1"},
		})
	}

	asn1Subj, err := asn1.Marshal(rawSubj)
	if err != nil {
		log.Println("Error in asn1.Marshal : ", err)
		return
	}
	template := x509.CertificateRequest{
		RawSubject: asn1Subj,
		// SignatureAlgorithm: x509.SHA256WithRSA,
		ExtraExtensions: getExtraExtensions(certSettings.EncryptedChallengePassword),
	}
	setDataFromCurrentCertificate(&template, certificate)

	err = setHashFunctionRSA(&template, certSettings)
	if err != nil {
		log.Println("Error in getting the hashFunction for RSA", err)
		return
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	if err != nil {
		log.Println("Error in x509.CreateCertificateRequest : ", err)
		return
	}
	csr = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	log.Println("Finished : genCSR")

	return
}

func getExtraExtensions(challangePassword string) []pkix.Extension {
	return []pkix.Extension{
		{
			Id:    asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7},
			Value: []byte(challangePassword),
		},
		// {
		// 	Id:    asn1.ObjectIdentifier{2, 5, 29, 17, 0},
		// 	Value: []byte("otherName"),
		// },
		// {
		// 	Id:    asn1.ObjectIdentifier{2, 5, 29, 17, 1},
		// 	Value: []byte("abc@abc.com"),
		// },
		// {
		// 	Id:    asn1.ObjectIdentifier{2, 5, 29, 17, 2},
		// 	Value: []byte("dNSName"),
		// },
		// {
		// 	Id:    asn1.ObjectIdentifier{2, 5, 29, 17, 4},
		// 	Value: []byte("CN=something.appviewx.com"),
		// },
		// {
		// 	Id:    asn1.ObjectIdentifier{2, 5, 29, 17, 5},
		// 	Value: []byte("http://www.google.com"),
		// },
		// {
		// 	Id:    asn1.ObjectIdentifier{2, 5, 29, 17, 6},
		// 	Value: []byte("1.1.1.1"),
		// },
		// {
		// 	Id:    asn1.ObjectIdentifier{2, 5, 29, 17, 7},
		// 	Value: []byte("1.3.6.1.5.5.7.8.5"),
		// },
	}
}

func setHashFunctionRSA(template *x509.CertificateRequest, certSettings *certSettings.CertSettings) (err error) {
	hashRequired := strings.ToLower(certSettings.HashFunction)
	switch hashRequired {
	case "sha160":
		template.SignatureAlgorithm = x509.SHA1WithRSA
	case "sha256":
		template.SignatureAlgorithm = x509.SHA256WithRSA
	case "sha384":
		template.SignatureAlgorithm = x509.SHA384WithRSA
	case "sha512":
		template.SignatureAlgorithm = x509.SHA512WithRSA
	case "md5":
		template.SignatureAlgorithm = x509.MD5WithRSA
	default:
		return errors.New("Given hash function : " + certSettings.HashFunction + " Not supported")
	}
	return nil
}

func setDataFromCurrentCertificate(template *x509.CertificateRequest, certificate *certificate.CurrentCert) {
	//TODO
	template.IPAddresses = getNetIPSliceForStringSlice(certificate.IPAddresses)
	template.DNSNames = certificate.DNSNames
	template.EmailAddresses = certificate.RFC822Names
	template.URIs = getURIs(certificate.UniformResourceIdentifiers)
	// template.Extensions = getExtension()
}

func getURIs(uris []string) (output []*url.URL) {
	output = []*url.URL{}
	for _, uri := range uris {
		output = append(output, &url.URL{Host: uri})
	}
	return
}

func getNetIPSliceForStringSlice(ipAddresses []string) []net.IP {
	output := []net.IP{}
	for _, ipAddress := range ipAddresses {
		output = append(output, net.ParseIP(ipAddress))
	}
	return output
}

func getExtension() []pkix.Extension {
	return []pkix.Extension{

		// {
		// 	Id:    asn1.ObjectIdentifier{2, 5, 29, 17, 0},
		// 	Value: []byte("otherName"),
		// },
		{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17, 1},
			Value: []byte("abc@abc.com"),
		},
		{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17, 2},
			Value: []byte("dNSName"),
		},
		{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17, 4},
			Value: []byte("CN=something.appviewx.com"),
		},
		{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17, 5},
			Value: []byte("http://www.google.com"),
		},
		{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17, 6},
			Value: []byte("1.1.1.1"),
		},
		{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17, 7},
			Value: []byte("1.3.6.1.5.5.7.8.5"),
		},
	}
}
