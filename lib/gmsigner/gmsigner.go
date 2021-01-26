package gmsigner

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/cloudflare/cfssl/info"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
	"io"
	"math/big"
	mathRand "math/rand"
	"net"
	"net/http"
	"net/mail"
	"time"

	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	x509GM "github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric/bccsp/gm"

	"github.com/cloudflare/cfssl/signer"
)

// add by thoughtwork's matrix
func OverrideHosts(template *x509GM.Certificate, hosts []string) {
	if hosts != nil {
		template.IPAddresses = []net.IP{}
		template.EmailAddresses = []string{}
		template.DNSNames = []string{}
	}

	for i := range hosts {
		if ip := net.ParseIP(hosts[i]); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(hosts[i]); err == nil && email != nil {
			template.EmailAddresses = append(template.EmailAddresses, email.Address)
		} else {
			template.DNSNames = append(template.DNSNames, hosts[i])
		}
	}
}

// replaceSliceIfEmpty replaces the contents of replaced with newContents if
// the slice referenced by replaced is empty
func replaceSliceIfEmpty(replaced, newContents *[]string) {
	if len(*replaced) == 0 {
		*replaced = *newContents
	}
}

// PopulateSubjectFromCSR has functionality similar to Name, except
// it fills the fields of the resulting pkix.Name with req's if the
// subject's corresponding fields are empty
func PopulateSubjectFromCSR(s *signer.Subject, req pkix.Name) pkix.Name {
	// if no subject, use req
	if s == nil {
		return req
	}
	name := s.Name()

	if name.CommonName == "" {
		name.CommonName = req.CommonName
	}

	replaceSliceIfEmpty(&name.Country, &req.Country)
	replaceSliceIfEmpty(&name.Province, &req.Province)
	replaceSliceIfEmpty(&name.Locality, &req.Locality)
	replaceSliceIfEmpty(&name.Organization, &req.Organization)
	replaceSliceIfEmpty(&name.OrganizationalUnit, &req.OrganizationalUnit)
	if name.SerialNumber == "" {
		name.SerialNumber = req.SerialNumber
	}
	return name
}

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func ComputeSKI(template *x509GM.Certificate) ([]byte, error) {
	pub := template.PublicKey
	encodedPub, err := x509GM.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	var subPKI subjectPublicKeyInfo
	_, err = asn1.Unmarshal(encodedPub, &subPKI)
	if err != nil {
		return nil, err
	}

	pubHash := sha1.Sum(subPKI.SubjectPublicKey.Bytes)
	return pubHash[:], nil
}

type policyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
	Qualifiers       []interface{} `asn1:"tag:optional,omitempty"`
}

type cpsPolicyQualifier struct {
	PolicyQualifierID asn1.ObjectIdentifier
	Qualifier         string `asn1:"tag:optional,ia5"`
}

type userNotice struct {
	ExplicitText string `asn1:"tag:optional,utf8"`
}
type userNoticePolicyQualifier struct {
	PolicyQualifierID asn1.ObjectIdentifier
	Qualifier         userNotice
}

var (
	// Per https://tools.ietf.org/html/rfc3280.html#page-106, this represents:
	// iso(1) identified-organization(3) dod(6) internet(1) security(5)
	//   mechanisms(5) pkix(7) id-qt(2) id-qt-cps(1)
	iDQTCertificationPracticeStatement = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}
	// iso(1) identified-organization(3) dod(6) internet(1) security(5)
	//   mechanisms(5) pkix(7) id-qt(2) id-qt-unotice(2)
	iDQTUserNotice = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2}
)

func addPolicies(template *x509GM.Certificate, policies []config.CertificatePolicy) error {
	var asn1PolicyList []policyInformation

	for _, policy := range policies {
		pi := policyInformation{
			// The PolicyIdentifier is an OID assigned to a given issuer.
			PolicyIdentifier: asn1.ObjectIdentifier(policy.ID),
		}
		for _, qualifier := range policy.Qualifiers {
			switch qualifier.Type {
			case "id-qt-unotice":
				pi.Qualifiers = append(pi.Qualifiers,
					userNoticePolicyQualifier{
						PolicyQualifierID: iDQTUserNotice,
						Qualifier: userNotice{
							ExplicitText: qualifier.Value,
						},
					})
			case "id-qt-cps":
				pi.Qualifiers = append(pi.Qualifiers,
					cpsPolicyQualifier{
						PolicyQualifierID: iDQTCertificationPracticeStatement,
						Qualifier:         qualifier.Value,
					})
			default:
				return errors.New("Invalid qualifier type in Policies " + qualifier.Type)
			}
		}
		asn1PolicyList = append(asn1PolicyList, pi)
	}

	asn1Bytes, err := asn1.Marshal(asn1PolicyList)
	if err != nil {
		return err
	}

	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 32},
		Critical: false,
		Value:    asn1Bytes,
	})
	return nil
}

func FillTemplate(template *x509GM.Certificate, defaultProfile, profile *config.SigningProfile, notBefore time.Time, notAfter time.Time) error {
	ski, err := ComputeSKI(template)
	if err != nil {
		return err
	}

	var (
		eku             []x509.ExtKeyUsage
		ku              x509.KeyUsage
		backdate        time.Duration
		expiry          time.Duration
		crlURL, ocspURL string
		issuerURL       = profile.IssuerURL
	)

	// The third value returned from Usages is a list of unknown key usages.
	// This should be used when validating the profile at load, and isn't used
	// here.
	ku, eku, _ = profile.Usages()
	sm2eku := make([]x509GM.ExtKeyUsage, len(eku))

	for i := 0; i < len(eku); i++ {
		sm2eku[i] = x509GM.ExtKeyUsage(eku[i])
	}

	if profile.IssuerURL == nil {
		issuerURL = defaultProfile.IssuerURL
	}

	if ku == 0 && len(eku) == 0 {
		return cferr.New(cferr.PolicyError, cferr.NoKeyUsages)
	}

	if expiry = profile.Expiry; expiry == 0 {
		expiry = defaultProfile.Expiry
	}

	if crlURL = profile.CRL; crlURL == "" {
		crlURL = defaultProfile.CRL
	}
	if ocspURL = profile.OCSP; ocspURL == "" {
		ocspURL = defaultProfile.OCSP
	}

	if notBefore.IsZero() {
		if !profile.NotBefore.IsZero() {
			notBefore = profile.NotBefore
		} else {
			if backdate = profile.Backdate; backdate == 0 {
				backdate = -5 * time.Minute
			} else {
				backdate = -1 * profile.Backdate
			}
			notBefore = time.Now().Round(time.Minute).Add(backdate)
		}
	}
	notBefore = notBefore.UTC()

	if notAfter.IsZero() {
		if !profile.NotAfter.IsZero() {
			notAfter = profile.NotAfter
		} else {
			notAfter = notBefore.Add(expiry)
		}
	}
	notAfter = notAfter.UTC()

	template.NotBefore = notBefore
	template.NotAfter = notAfter
	template.KeyUsage = x509GM.KeyUsage(ku)
	template.ExtKeyUsage = sm2eku
	template.BasicConstraintsValid = true
	template.IsCA = profile.CAConstraint.IsCA
	if template.IsCA {
		template.MaxPathLen = profile.CAConstraint.MaxPathLen
		if template.MaxPathLen == 0 {
			template.MaxPathLenZero = profile.CAConstraint.MaxPathLenZero
		}
		template.DNSNames = nil
		template.EmailAddresses = nil
	}
	template.SubjectKeyId = ski

	if ocspURL != "" {
		template.OCSPServer = []string{ocspURL}
	}
	if crlURL != "" {
		template.CRLDistributionPoints = []string{crlURL}
	}

	if len(issuerURL) != 0 {
		template.IssuingCertificateURL = issuerURL
	}
	if len(profile.Policies) != 0 {
		err = addPolicies(template, profile.Policies)
		if err != nil {
			return cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy, err)
		}
	}
	if profile.OCSPNoCheck {
		ocspNoCheckExtension := pkix.Extension{
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5},
			Critical: false,
			Value:    []byte{0x05, 0x00},
		}
		template.ExtraExtensions = append(template.ExtraExtensions, ocspNoCheckExtension)
	}

	return nil
}

//证书请求转换成证书  参数为  block .Bytes
func parseCertificateRequest(s signer.Signer, csrBytes []byte) (template *x509GM.Certificate, err error) {
	csrv, err := x509GM.ParseCertificateRequest(csrBytes)
	if err != nil {
		err = cferr.Wrap(cferr.CSRError, cferr.ParseFailed, err)
		return
	}
	err = csrv.CheckSignature()
	if err != nil {
		err = cferr.Wrap(cferr.CSRError, cferr.KeyMismatch, err)
		return
	}

	ecdsaPublicKey, ok := csrv.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.Errorf("need ecdsa public key")
	}

	template = &x509GM.Certificate{
		Subject:            csrv.Subject,
		PublicKeyAlgorithm: csrv.PublicKeyAlgorithm,
		PublicKey:          &sm2.PublicKey{Curve: sm2.P256Sm2(), X: ecdsaPublicKey.X, Y: ecdsaPublicKey.Y},
		SignatureAlgorithm: x509GM.SignatureAlgorithm(s.SigAlgo()),
		DNSNames:           csrv.DNSNames,
		IPAddresses:        csrv.IPAddresses,
		EmailAddresses:     csrv.EmailAddresses,
	}

	template.NotBefore = time.Now()
	template.NotAfter = time.Now().Add(time.Hour * 1000)

	for _, val := range csrv.Extensions {
		// Check the CSR for the X.509 BasicConstraints (RFC 5280, 4.2.1.9)
		// extension and append to template if necessary
		if val.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}) {
			var constraints csr.BasicConstraints
			var rest []byte

			if rest, err = asn1.Unmarshal(val.Value, &constraints); err != nil {
				return nil, cferr.Wrap(cferr.CSRError, cferr.ParseFailed, err)
			} else if len(rest) != 0 {
				return nil, cferr.Wrap(cferr.CSRError, cferr.ParseFailed, errors.New("x509: trailing data after X.509 BasicConstraints"))
			}

			template.BasicConstraintsValid = true
			template.IsCA = constraints.IsCA
			template.MaxPathLen = constraints.MaxPathLen
			template.MaxPathLenZero = template.MaxPathLen == 0
		}
	}
	serialNumber := make([]byte, 20)
	_, err = io.ReadFull(rand.Reader, serialNumber)
	if err != nil {
		return nil, err
	}

	// SetBytes interprets buf as the bytes of a big-endian
	// unsigned integer. The leading byte should be masked
	// off to ensure it isn't negative.
	serialNumber[0] &= 0x7F

	template.SerialNumber = new(big.Int).SetBytes(serialNumber)

	return
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[mathRand.Intn(len(letters))]
	}
	return string(b)
}

//cloudflare 证书请求 转成 国密证书请求
func GenerateGMCsr(priv crypto.Signer, req *csr.CertificateRequest) (csr []byte, err error) {
	sigAlgo := signerAlgo(priv)
	if sigAlgo == x509GM.UnknownSignatureAlgorithm {
		return nil, fmt.Errorf("private key is unavailable")
	}
	var tpl = x509GM.CertificateRequest{
		Subject:            req.Name(),
		SignatureAlgorithm: sigAlgo,
	}
	for i := range req.Hosts {
		if ip := net.ParseIP(req.Hosts[i]); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(req.Hosts[i]); err == nil && email != nil {
			tpl.EmailAddresses = append(tpl.EmailAddresses, email.Address)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, req.Hosts[i])
		}
	}

	if req.CA != nil {
		err = appendCAInfoToCSRSm2(req.CA, &tpl)
		if err != nil {
			err = fmt.Errorf("sm2 GenerationFailed")
			return
		}
	}

	if req.SerialNumber != "" {
		req.SerialNumber = randSeq(65)
	}

	csr, err = gm.CreateSm2CertificateRequestToMem(&tpl, priv)
	return csr, err
}

func signerAlgo(priv crypto.Signer) x509GM.SignatureAlgorithm {
	switch pub := priv.Public().(type) {
	case *sm2.PublicKey:
		switch pub.Curve {
		case sm2.P256Sm2():
			return x509GM.SM2WithSM3
		default:
			return x509GM.SM2WithSM3
		}
	default:
		return x509GM.UnknownSignatureAlgorithm
	}
}

// appendCAInfoToCSR appends CAConfig BasicConstraint extension to a CSR
func appendCAInfoToCSRSm2(reqConf *csr.CAConfig, csreq *x509GM.CertificateRequest) error {
	pathlen := reqConf.PathLength
	if pathlen == 0 && !reqConf.PathLenZero {
		pathlen = -1
	}
	val, err := asn1.Marshal(csr.BasicConstraints{IsCA: true, MaxPathLen: pathlen})

	if err != nil {
		return err
	}

	csreq.ExtraExtensions = []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
			Value:    val,
			Critical: true,
		},
	}

	return nil
}

type GMSigner struct {
	ca         *x509GM.Certificate
	priv       crypto.Signer
	policy     *config.Signing
	sigAlgo    x509GM.SignatureAlgorithm
	dbAccessor certdb.Accessor
}

func (s *GMSigner) Info(req info.Req) (resp *info.Resp, err error) {
	cert, err := s.Certificate(req.Label, req.Profile)
	if err != nil {
		return
	}

	profile, err := signer.Profile(s, req.Profile)
	if err != nil {
		return
	}

	resp = new(info.Resp)
	if cert.Raw != nil {
		resp.Certificate = string(bytes.TrimSpace(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
	}
	resp.Usage = profile.Usage
	resp.ExpiryString = profile.ExpiryString

	return
}

// Profile gets the specific profile from the signer
func Profile(s signer.Signer, profile string) (*config.SigningProfile, error) {
	var p *config.SigningProfile
	policy := s.Policy()
	if policy != nil && policy.Profiles != nil && profile != "" {
		p = policy.Profiles[profile]
	}

	if p == nil && policy != nil {
		p = policy.Default
	}

	if p == nil {
		return nil, cferr.Wrap(cferr.APIClientError, cferr.ClientHTTPError, errors.New("profile must not be nil"))
	}
	return p, nil
}

func NewSigner(priv crypto.Signer, cert *x509.Certificate, sigAlgo x509GM.SignatureAlgorithm, policy *config.Signing) (*GMSigner, error) {
	if policy == nil {
		policy = &config.Signing{
			Profiles: map[string]*config.SigningProfile{},
			Default:  config.DefaultConfig(),
		}
	}
	if !policy.Valid() {
		return nil, cferr.New(cferr.PolicyError, cferr.InvalidPolicy)
	}

	var ca *x509GM.Certificate
	if cert != nil {
		ca = gm.ParseX509Certificate2Sm2(cert)
	}

	return &GMSigner{
		ca:      ca,
		priv:    priv,
		sigAlgo: sigAlgo,
		policy:  policy,
	}, nil
}

func (s *GMSigner) sign(template *x509GM.Certificate, profile *config.SigningProfile, notBefore time.Time, notAfter time.Time) (cert []byte, err error) {
	var distPoints = template.CRLDistributionPoints
	if distPoints != nil && len(distPoints) > 0 {
		template.CRLDistributionPoints = distPoints
	}
	err = FillTemplate(template, s.policy.Default, profile, notBefore, notAfter)
	if err != nil {
		return nil, err
	}

	var initRoot bool
	if s.ca == nil {
		if !template.IsCA {
			err = cferr.New(cferr.PolicyError, cferr.InvalidRequest)
			return
		}
		template.DNSNames = nil
		template.EmailAddresses = nil
		s.ca = template
		initRoot = true
	}

	derBytes, err := x509GM.CreateCertificate(template, s.ca, template.PublicKey.(*sm2.PublicKey), s.priv)
	if err != nil {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.Unknown, err)
	}
	if initRoot {
		s.ca, err = x509GM.ParseCertificate(derBytes)
		if err != nil {
			return nil, cferr.Wrap(cferr.CertificateError, cferr.ParseFailed, err)
		}
	}

	cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	log.Infof("signed certificate with serial number %d", template.SerialNumber)
	return
}

func (s *GMSigner) Sign(req signer.SignRequest) (cert []byte, err error) {
	profile, err := Profile(s, req.Profile)
	if err != nil {
		return
	}

	block, _ := pem.Decode([]byte(req.Request))
	if block == nil {
		return nil, cferr.New(cferr.CSRError, cferr.DecodeFailed)
	}

	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return nil, cferr.Wrap(cferr.CSRError,
			cferr.BadRequest, errors.New("not a csr"))
	}

	csrTemplate, err := parseCertificateRequest(s, block.Bytes)
	if err != nil {
		return nil, err
	}

	// Copy out only the fields from the CSR authorized by policy.
	safeTemplate := x509GM.Certificate{}
	// If the profile contains no explicit whitelist, assume that all fields
	// should be copied from the CSR.
	if profile.CSRWhitelist == nil {
		safeTemplate = *csrTemplate
	} else {
		if profile.CSRWhitelist.Subject {
			safeTemplate.Subject = csrTemplate.Subject
		}
		if profile.CSRWhitelist.PublicKeyAlgorithm {
			safeTemplate.PublicKeyAlgorithm = csrTemplate.PublicKeyAlgorithm
		}
		if profile.CSRWhitelist.PublicKey {
			safeTemplate.PublicKey = csrTemplate.PublicKey
		}
		if profile.CSRWhitelist.SignatureAlgorithm {
			safeTemplate.SignatureAlgorithm = csrTemplate.SignatureAlgorithm
		}
		if profile.CSRWhitelist.DNSNames {
			safeTemplate.DNSNames = csrTemplate.DNSNames
		}
		if profile.CSRWhitelist.IPAddresses {
			safeTemplate.IPAddresses = csrTemplate.IPAddresses
		}
		if profile.CSRWhitelist.EmailAddresses {
			safeTemplate.EmailAddresses = csrTemplate.EmailAddresses
		}
	}

	if req.CRLOverride != "" {
		safeTemplate.CRLDistributionPoints = []string{req.CRLOverride}
	}

	if safeTemplate.IsCA {
		if !profile.CAConstraint.IsCA {
			log.Error("local signer policy disallows issuing CA certificate")
			return nil, cferr.New(cferr.PolicyError, cferr.InvalidRequest)
		}

		if s.ca != nil && s.ca.MaxPathLen > 0 {
			if safeTemplate.MaxPathLen >= s.ca.MaxPathLen {
				log.Error("local signer certificate disallows CA MaxPathLen extending")
				// do not sign a cert with pathlen > current
				return nil, cferr.New(cferr.PolicyError, cferr.InvalidRequest)
			}
		} else if s.ca != nil && s.ca.MaxPathLen == 0 && s.ca.MaxPathLenZero {
			log.Error("local signer certificate disallows issuing CA certificate")
			// signer has pathlen of 0, do not sign more intermediate CAs
			return nil, cferr.New(cferr.PolicyError, cferr.InvalidRequest)
		}
	}

	OverrideHosts(&safeTemplate, req.Hosts)
	safeTemplate.Subject = PopulateSubjectFromCSR(req.Subject, safeTemplate.Subject)

	// If there is a whitelist, ensure that both the Common Name and SAN DNSNames match
	if profile.NameWhitelist != nil {
		if safeTemplate.Subject.CommonName != "" {
			if profile.NameWhitelist.Find([]byte(safeTemplate.Subject.CommonName)) == nil {
				return nil, cferr.New(cferr.PolicyError, cferr.UnmatchedWhitelist)
			}
		}
		for _, name := range safeTemplate.DNSNames {
			if profile.NameWhitelist.Find([]byte(name)) == nil {
				return nil, cferr.New(cferr.PolicyError, cferr.UnmatchedWhitelist)
			}
		}
		for _, name := range safeTemplate.EmailAddresses {
			if profile.NameWhitelist.Find([]byte(name)) == nil {
				return nil, cferr.New(cferr.PolicyError, cferr.UnmatchedWhitelist)
			}
		}
	}

	if profile.ClientProvidesSerialNumbers {
		if req.Serial == nil {
			return nil, cferr.New(cferr.CertificateError, cferr.MissingSerial)
		}
		safeTemplate.SerialNumber = req.Serial
	} else {
		// RFC 5280 4.1.2.2:
		// Certificate users MUST be able to handle serialNumber
		// values up to 20 octets.  Conforming CAs MUST NOT use
		// serialNumber values longer than 20 octets.
		//
		// If CFSSL is providing the serial numbers, it makes
		// sense to use the max supported size.
		serialNumber := make([]byte, 20)
		_, err = io.ReadFull(rand.Reader, serialNumber)
		if err != nil {
			return nil, cferr.Wrap(cferr.CertificateError, cferr.Unknown, err)
		}

		// SetBytes interprets buf as the bytes of a big-endian
		// unsigned integer. The leading byte should be masked
		// off to ensure it isn't negative.
		serialNumber[0] &= 0x7F

		safeTemplate.SerialNumber = new(big.Int).SetBytes(serialNumber)
	}

	if len(req.Extensions) > 0 {
		for _, ext := range req.Extensions {
			oid := asn1.ObjectIdentifier(ext.ID)
			if !profile.ExtensionWhitelist[oid.String()] {
				return nil, cferr.New(cferr.CertificateError, cferr.InvalidRequest)
			}

			rawValue, err := hex.DecodeString(ext.Value)
			if err != nil {
				return nil, cferr.Wrap(cferr.CertificateError, cferr.InvalidRequest, err)
			}

			safeTemplate.ExtraExtensions = append(safeTemplate.ExtraExtensions, pkix.Extension{
				Id:       oid,
				Critical: ext.Critical,
				Value:    rawValue,
			})
		}
	}

	var certTBS = safeTemplate

	if len(profile.CTLogServers) > 0 {
		// Add a poison extension which prevents validation
		var poisonExtension = pkix.Extension{Id: signer.CTPoisonOID, Critical: true, Value: []byte{0x05, 0x00}}
		var poisonedPreCert = certTBS
		poisonedPreCert.ExtraExtensions = append(safeTemplate.ExtraExtensions, poisonExtension)
		cert, err = s.sign(&poisonedPreCert, profile, req.NotBefore, req.NotAfter)
		if err != nil {
			return
		}

		derCert, _ := pem.Decode(cert)
		prechain := []ct.ASN1Cert{{Data: derCert.Bytes}, {Data: s.ca.Raw}}
		var sctList []ct.SignedCertificateTimestamp

		for _, server := range profile.CTLogServers {
			log.Infof("submitting poisoned precertificate to %s", server)
			ctclient, err := client.New(server, nil, jsonclient.Options{})
			if err != nil {
				return nil, cferr.Wrap(cferr.CTError, cferr.PrecertSubmissionFailed, err)
			}
			var resp *ct.SignedCertificateTimestamp
			ctx := context.Background()
			resp, err = ctclient.AddPreChain(ctx, prechain)
			if err != nil {
				return nil, cferr.Wrap(cferr.CTError, cferr.PrecertSubmissionFailed, err)
			}
			sctList = append(sctList, *resp)
		}

		var serializedSCTList []byte
		serializedSCTList, err = helpers.SerializeSCTList(sctList)
		if err != nil {
			return nil, cferr.Wrap(cferr.CTError, cferr.Unknown, err)
		}

		// Serialize again as an octet string before embedding
		serializedSCTList, err = asn1.Marshal(serializedSCTList)
		if err != nil {
			return nil, cferr.Wrap(cferr.CTError, cferr.Unknown, err)
		}

		var SCTListExtension = pkix.Extension{Id: signer.SCTListOID, Critical: false, Value: serializedSCTList}
		certTBS.ExtraExtensions = append(certTBS.ExtraExtensions, SCTListExtension)
	}
	var signedCert []byte
	signedCert, err = s.sign(&certTBS, profile, req.NotBefore, req.NotAfter)
	if err != nil {
		return nil, err
	}

	// Get the AKI from signedCert.  This is required to support Go 1.9+.
	// In prior versions of Go, x509.CreateCertificate updated the
	// AuthorityKeyId of certTBS.
	parsedCert, _ := x509GM.ReadCertificateFromPem(signedCert)

	if s.dbAccessor != nil {
		var certRecord = certdb.CertificateRecord{
			Serial: certTBS.SerialNumber.String(),
			// this relies on the specific behavior of x509.CreateCertificate
			// which sets the AuthorityKeyId from the signer's SubjectKeyId
			AKI:     hex.EncodeToString(parsedCert.AuthorityKeyId),
			CALabel: req.Label,
			Status:  "good",
			Expiry:  certTBS.NotAfter,
			PEM:     string(signedCert),
		}

		err = s.dbAccessor.InsertCertificate(certRecord)
		if err != nil {
			return nil, err
		}
		log.Debug("saved certificate with serial number ", certTBS.SerialNumber)
	}

	return signedCert, nil
}

// Certificate returns the signer's certificate.
func (s *GMSigner) Certificate(_, _ string) (*x509GM.Certificate, error) {
	cert := *s.ca
	return &cert, nil
}

func (s *GMSigner) Policy() *config.Signing {
	return s.policy
}

func (s *GMSigner) SetDBAccessor(dba certdb.Accessor) {
	s.dbAccessor = dba
}

func (s *GMSigner) GetDBAccessor() certdb.Accessor {
	return s.dbAccessor
}

func (s *GMSigner) SetPolicy(policy *config.Signing) {
	s.policy = policy
}

func (s *GMSigner) SigAlgo() x509.SignatureAlgorithm {
	return x509.SignatureAlgorithm(s.sigAlgo)
}

func (s *GMSigner) SetReqModifier(_ func(*http.Request, []byte)) {
	//  noop
}
