package pkg

import (
	"github.com/algotuners-v2/zerodha-free-tier-go_sdk/pkg/constants"
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
