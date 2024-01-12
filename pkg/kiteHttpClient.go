package pkg

import (
	"fmt"
	"github.com/algotuners-v2/zerodha-free-tier-go_sdk/pkg/constants"
	httpUtils2 "github.com/algotuners-v2/zerodha-free-tier-go_sdk/pkg/httpUtils"
	"net/http"
	"net/url"
	"time"
)

type KiteHttpClient struct {
	encToken    string
	apiKey      string
	accessToken string
	debug       bool
	baseURI     string
	httpClient  httpUtils2.HTTPClient
}

func (kiteHttpClient *KiteHttpClient) SetHTTPClient(h *http.Client) {
	kiteHttpClient.httpClient = httpUtils2.GenerateHttpClient(h, kiteHttpClient.debug)
}

func (kiteHttpClient *KiteHttpClient) SetDebug(debug bool) {
	kiteHttpClient.debug = debug
	kiteHttpClient.httpClient.GetClient().Debug = debug
}

func (kiteHttpClient *KiteHttpClient) SetBaseURI(baseURI string) {
	kiteHttpClient.baseURI = baseURI
}

func (kiteHttpClient *KiteHttpClient) SetTimeout(timeout time.Duration) {
	hClient := kiteHttpClient.httpClient.GetClient().Client
	hClient.Timeout = timeout
}

func (kiteHttpClient *KiteHttpClient) SetEncToken(encToken string) {
	kiteHttpClient.encToken = encToken
}

func (kiteHttpClient *KiteHttpClient) SetAccessToken(accessToken string) {
	kiteHttpClient.accessToken = accessToken
}

func (kiteHttpClient *KiteHttpClient) SetApiKey(apiKey string) {
	kiteHttpClient.apiKey = apiKey
}

func (kiteHttpClient *KiteHttpClient) GetEncToken() string {
	return kiteHttpClient.encToken
}

func (kiteHttpClient *KiteHttpClient) GetLoginURL() string {
	return fmt.Sprintf("%s/connect/login?api_key=%s&v=%s", constants.KiteBaseURI, kiteHttpClient.apiKey, constants.KiteHeaderVersion)
}

func (kiteHttpClient *KiteHttpClient) doEnvelope(method, uri string, params url.Values, headers http.Header, v interface{}) error {
	if params == nil {
		params = url.Values{}
	}
	if headers == nil {
		headers = map[string][]string{}
	}
	headers.Add("X-Kite-Version", constants.KiteHeaderVersion)
	headers.Add("User-Agent", constants.Name+"/"+constants.Version)
	if kiteHttpClient.encToken != "" {
		authHeader := fmt.Sprintf("enctoken %s", kiteHttpClient.encToken)
		headers.Add("Authorization", authHeader)
	}
	return kiteHttpClient.httpClient.DoEnvelope(method, kiteHttpClient.baseURI+uri, params, headers, v)
}

func (kiteHttpClient *KiteHttpClient) do(method, uri string, params url.Values, headers http.Header) (httpUtils2.HTTPResponse, error) {
	if params == nil {
		params = url.Values{}
	}
	if headers == nil {
		headers = map[string][]string{}
	}
	headers.Add("X-Kite-Version", constants.KiteHeaderVersion)
	headers.Add("User-Agent", constants.Name+"/"+constants.Version)
	if kiteHttpClient.encToken != "" {
		authHeader := fmt.Sprintf("enctoken %s", kiteHttpClient.encToken)
		headers.Add("Authorization", authHeader)
	}
	return kiteHttpClient.httpClient.Do(method, kiteHttpClient.baseURI+uri, params, headers)
}

func (kiteHttpClient *KiteHttpClient) doRaw(method, uri string, reqBody []byte, headers http.Header) (httpUtils2.HTTPResponse, error) {
	if headers == nil {
		headers = map[string][]string{}
	}
	headers.Add("X-Kite-Version", constants.KiteHeaderVersion)
	headers.Add("User-Agent", constants.Name+"/"+constants.Version)
	if kiteHttpClient.encToken != "" {
		authHeader := fmt.Sprintf("enctoken %s", kiteHttpClient.encToken)
		headers.Add("Authorization", authHeader)
	}
	return kiteHttpClient.httpClient.DoRaw(method, kiteHttpClient.baseURI+uri, reqBody, headers)
}
