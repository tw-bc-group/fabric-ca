package gmca

import (
	"crypto"
	x509GM "github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/hyperledger/fabric-ca/lib/gmsigner"
	"time"

	"github.com/cloudflare/cfssl/csr"
)

// CAPolicy contains the CA issuing policy as default policy.
var CAPolicy = func() *config.Signing {
	return &config.Signing{
		Default: &config.SigningProfile{
			Usage:        []string{"cert sign", "crl sign"},
			ExpiryString: "43800h",
			Expiry:       5 * helpers.OneYear,
			CAConstraint: config.CAConstraint{IsCA: true},
		},
	}
}

func NewFromSigner(req *csr.CertificateRequest, priv crypto.Signer) (cert, csrPEM []byte, err error) {
	policy := CAPolicy()
	if req.CA != nil {
		if req.CA.Expiry != "" {
			policy.Default.ExpiryString = req.CA.Expiry
			policy.Default.Expiry, err = time.ParseDuration(req.CA.Expiry)
			if err != nil {
				return nil, nil, err
			}
		}

		policy.Default.CAConstraint.MaxPathLen = req.CA.PathLength
		if req.CA.PathLength != 0 && req.CA.PathLenZero == true {
			log.Infof("ignore invalid 'pathlenzero' value")
		} else {
			policy.Default.CAConstraint.MaxPathLenZero = req.CA.PathLenZero
		}
	}

	csrPEM, err = gmsigner.GenerateGMCsr(priv, req)
	if err != nil {
		return nil, nil, err
	}

	s, err := gmsigner.NewSigner(priv, nil, x509GM.SM2WithSM3, policy)
	if err != nil {
		log.Errorf("failed to create signer: %v", err)
		return
	}

	signReq := signer.SignRequest{Request: string(csrPEM)}
	cert, err = s.Sign(signReq)
	return
}
