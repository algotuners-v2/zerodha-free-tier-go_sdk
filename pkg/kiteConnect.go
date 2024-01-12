package pkg

import (
	"github.com/algotuners/zerodha-sdk-go/pkg/constants"
	"net/http"
)

func KiteConnect(encToken string, apiKey string) *KiteHttpClient {
	client := &KiteHttpClient{}
	client.SetHTTPClient(&http.Client{
		Timeout: constants.RequestTimeout,
	})
	client.SetBaseURI(constants.BaseURI)
	client.SetEncToken(encToken)
	client.SetApiKey(apiKey)
	return client
}
