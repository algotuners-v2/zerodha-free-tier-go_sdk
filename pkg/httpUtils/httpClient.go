package httpUtils

import (
	"net/http"
	"net/url"
)

type HTTPClient interface {
	Do(method, rURL string, params url.Values, headers http.Header) (HTTPResponse, error)
	DoRaw(method, rURL string, reqBody []byte, headers http.Header) (HTTPResponse, error)
	DoEnvelope(method, url string, params url.Values, headers http.Header, obj interface{}) error
	DoJSON(method, url string, params url.Values, headers http.Header, obj interface{}) (HTTPResponse, error)
	GetClient() *BaseHttpClient
}
