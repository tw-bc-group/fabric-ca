package comm

import (
	"errors"
	"os"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

func CreateKmsClient() (*kms.Client, error) {
	region := os.Getenv("ALIBABA_CLOUD_REGION")
	accessKeyID := os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID")
	accessKeySecret := os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET")

	if len(region) == 0 || len(accessKeyID) == 0 || len(accessKeySecret) == 0 {
		return nil, errors.New("ALIBABA_CLOUD_REGION, ALIBABA_CLOUD_ACCESS_KEY_SECRET, ALIBABA_CLOUD_ACCESS_KEY_SECRET must be set")
	}

	client, err := kms.NewClientWithAccessKey(region, accessKeyID, accessKeySecret)
	if err != nil {
		return nil, err
	}
	return client, nil
}
