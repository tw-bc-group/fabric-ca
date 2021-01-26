package sm2

import (
	"crypto"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
	"github.com/tw-bc-group/aliyun-kms/comm"
	"io"
)

const requestScheme = "https"
const sm2SignAlgorithm = "SM2DSA"
const sm2EncryptAlgorithm = "SM2PKE"
const maxPageSize = 100

const (
	EncryptAndDecrypt = 1 + iota
	SignAndVerify
)

type KeyAdapter struct {
	client     *kms.Client
	usage      int
	keyID      string
	keyVersion string
	publicKey  *sm2.PublicKey
}

func (adapter *KeyAdapter) sm3Digest(message []byte) (string, error) {
	publicKey := adapter.Public().(*sm2.PublicKey)
	digest, err := publicKey.Sm3Digest(message, []byte{})
	if err != nil {
		return "", nil
	}

	return base64.StdEncoding.EncodeToString(digest), nil
}

func keyUsageString(keyUsage int) string {
	switch keyUsage {
	case EncryptAndDecrypt:
		return "ENCRYPT/DECRYPT"
	default:
		return "SIGN/VERIFY"
	}
}

func (adapter *KeyAdapter) getPublicKey() (*sm2.PublicKey, error) {
	request := kms.CreateGetPublicKeyRequest()
	request.Scheme = requestScheme
	request.KeyId = adapter.keyID
	request.KeyVersionId = adapter.keyVersion

	response, err := adapter.client.GetPublicKey(request)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(response.PublicKey))
	pubKey, err := x509.ParseSm2PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

func CreateSm2KeyAdapter(keyID string, usage int) (*KeyAdapter, error) {
	if usage != EncryptAndDecrypt && usage != SignAndVerify {
		usage = SignAndVerify
	}

	client, err := comm.CreateKmsClient()
	if err != nil {
		return nil, err
	}

	adapter := &KeyAdapter{
		client: client,
		usage:  usage,
		keyID:  keyID,
	}

	err = adapter.CreateKey()
	if err != nil {
		return nil, err
	}

	adapter.publicKey, err = adapter.getPublicKey()
	if err != nil {
		return nil, err
	}

	return adapter, nil
}

func (adapter *KeyAdapter) PublicKey() *sm2.PublicKey {
	return adapter.publicKey
}

func (adapter *KeyAdapter) KeyID() string {
	return adapter.keyID
}

func (adapter *KeyAdapter) CreateKey() error {
	// set keyID already
	if adapter.keyID == "" {
		request := kms.CreateCreateKeyRequest()
		request.Scheme = requestScheme
		request.KeySpec = "EC_SM2"
		request.KeyUsage = keyUsageString(adapter.usage)

		response, err := adapter.client.CreateKey(request)
		if err != nil {
			return err
		}
		adapter.keyID = response.KeyMetadata.KeyId
	}

	request := kms.CreateListKeyVersionsRequest()
	request.Scheme = requestScheme
	request.KeyId = adapter.keyID

	response, err := adapter.client.ListKeyVersions(request)
	if err != nil {
		return err
	}

	adapter.keyVersion = response.KeyVersions.KeyVersion[0].KeyVersionId

	return nil
}

func (adapter *KeyAdapter) AsymmetricSign(message []byte) ([]byte, error) {
	if adapter.keyID == "" || adapter.keyVersion == "" {
		return nil, errors.New("need create adapter key first")
	}

	if adapter.usage != SignAndVerify {
		return nil, errors.New("unexpected key usage")
	}

	digest, err := adapter.sm3Digest(message)
	if err != nil {
		return nil, err
	}

	request := kms.CreateAsymmetricSignRequest()
	request.Scheme = requestScheme
	request.KeyId = adapter.keyID
	request.Algorithm = sm2SignAlgorithm
	request.KeyVersionId = adapter.keyVersion
	request.Digest = digest

	response, err := adapter.client.AsymmetricSign(request)
	if err != nil {
		return nil, err
	}

	signature, err := base64.StdEncoding.DecodeString(response.Value)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (adapter *KeyAdapter) AsymmetricVerify(message, signature []byte) (bool, error) {
	if adapter.keyID == "" || adapter.keyVersion == "" {
		return false, errors.New("need create adapter key first")
	}

	if adapter.usage != SignAndVerify {
		return false, errors.New("unexpected key usage")
	}

	digest, err := adapter.sm3Digest(message)
	if err != nil {
		return false, err
	}

	request := kms.CreateAsymmetricVerifyRequest()
	request.Scheme = requestScheme
	request.KeyId = adapter.keyID
	request.Algorithm = sm2SignAlgorithm
	request.KeyVersionId = adapter.keyVersion
	request.Digest = digest
	request.Value = base64.StdEncoding.EncodeToString(signature)

	response, err := adapter.client.AsymmetricVerify(request)

	if err != nil {
		return false, err
	}

	return response.Value, nil
}

func (adapter *KeyAdapter) AsymmetricEncrypt(plain []byte) ([]byte, error) {
	if adapter.keyID == "" || adapter.keyVersion == "" {
		return nil, errors.New("need create adapter key first")
	}

	if adapter.usage != EncryptAndDecrypt {
		return nil, errors.New("unexpected key usage")
	}

	request := kms.CreateAsymmetricEncryptRequest()
	request.Scheme = requestScheme
	request.KeyId = adapter.keyID
	request.KeyVersionId = adapter.keyVersion
	request.Algorithm = sm2EncryptAlgorithm
	request.Plaintext = base64.StdEncoding.EncodeToString(plain)

	response, err := adapter.client.AsymmetricEncrypt(request)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(response.CiphertextBlob)
}

func (adapter *KeyAdapter) AsymmetricDecrypt(cipher []byte) ([]byte, error) {
	if adapter.keyID == "" || adapter.keyVersion == "" {
		return nil, errors.New("need create adapter key first")
	}

	if adapter.usage != EncryptAndDecrypt {
		return nil, errors.New("unexpected key usage")
	}

	request := kms.CreateAsymmetricDecryptRequest()
	request.Scheme = requestScheme
	request.KeyId = adapter.keyID
	request.KeyVersionId = adapter.keyVersion
	request.Algorithm = sm2EncryptAlgorithm
	request.CiphertextBlob = base64.StdEncoding.EncodeToString(cipher)

	response, err := adapter.client.AsymmetricDecrypt(request)
	if err != nil {
		return nil, err
	}

	plainText, err := base64.StdEncoding.DecodeString(response.Plaintext)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

func (adapter *KeyAdapter) ScheduleKeyDeletion() error {
	request := kms.CreateScheduleKeyDeletionRequest()
	request.Scheme = requestScheme
	request.KeyId = adapter.keyID
	request.PendingWindowInDays = requests.NewInteger(7)

	_, err := adapter.client.ScheduleKeyDeletion(request)
	return err
}

// implements crypto.Signer
func (adapter *KeyAdapter) Public() crypto.PublicKey {
	return adapter.publicKey
}

func (adapter *KeyAdapter) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	return adapter.AsymmetricSign(message)
}

// implements crypto.Decrypter
func (adapter *KeyAdapter) Decrypt(_ io.Reader, msg []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	return adapter.AsymmetricDecrypt(msg)
}

func ListKyes() ([]string, error) {
	keyIds := []string{}
	page := 1
	for {
		keys, isContinue, err := listKeys(keyIds, page)
		if err != nil {
			return nil, err
		}

		keyIds = keys

		if isContinue {
			page++
		} else {
			return keyIds, nil
		}
	}
}

func listKeys(keyIds []string, page int) ([]string, bool, error) {
	client, err := comm.CreateKmsClient()
	request := kms.CreateListKeysRequest()
	request.PageNumber = requests.NewInteger(page)
	request.PageSize = requests.NewInteger(maxPageSize)
	// Only list Enabled EC_SM2 keys
	request.Filters = `[{"Key":"KeySpec", "Values":["EC_SM2"]}, {"Key":"KeyState", "Values":["Enabled"]}]`
	request.Scheme = requestScheme

	response, err := client.ListKeys(request)
	if err != nil {
		return keyIds, false, err
	}

	if !response.IsSuccess() {
		return keyIds, false, errors.New(response.String())
	}

	for _, k := range response.Keys.Key {
		keyIds = append(keyIds, k.KeyId)
	}

	if response.PageSize*response.PageNumber < response.TotalCount {
		return keyIds, true, nil
	} else {
		return keyIds, false, nil
	}
}
