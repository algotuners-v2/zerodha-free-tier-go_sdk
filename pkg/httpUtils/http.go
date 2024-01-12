package httpUtils

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

type BaseHttpClient struct {
	Client  *http.Client
	httpLog *log.Logger
	Debug   bool
}

type HTTPResponse struct {
	Body     []byte
	Response *http.Response
}

func GenerateHttpClient(httpClient *http.Client, debug bool) HTTPClient {
	httpLog := log.New(os.Stdout, "base.HTTP: ", log.Ldate|log.Ltime|log.Lshortfile)
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: time.Duration(5) * time.Second,
			Transport: &http.Transport{
				MaxIdleConnsPerHost:   10,
				ResponseHeaderTimeout: time.Second * time.Duration(5),
			},
		}
	}
	return &BaseHttpClient{
		httpLog: httpLog,
		Client:  httpClient,
		Debug:   debug,
	}
}

func (baseHttpClient *BaseHttpClient) Do(method, rURL string, params url.Values, headers http.Header) (HTTPResponse, error) {
	if params == nil {
		params = url.Values{}
	}
	return baseHttpClient.DoRaw(method, rURL, []byte(params.Encode()), headers)
}

func (baseHttpClient *BaseHttpClient) DoRaw(method, rURL string, reqBody []byte, headers http.Header) (HTTPResponse, error) {
	var (
		httpResponse = HTTPResponse{}
		err          error
		postBody     io.Reader
	)

	if method == http.MethodPost || method == http.MethodPut {
		postBody = bytes.NewReader(reqBody)
	}

	req, err := http.NewRequest(method, rURL, postBody)
	if err != nil {
		baseHttpClient.httpLog.Printf("Request preparation failed: %v", err)
		return httpResponse, NewErrorHelper(NetworkError, "Request preparation failed.", nil)
	}

	if headers != nil {
		req.Header = headers
	}

	if req.Header.Get("Content-Type") == "" {
		if method == http.MethodPost || method == http.MethodPut {
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	if method == http.MethodGet || method == http.MethodDelete {
		req.URL.RawQuery = string(reqBody)
	}

	clientResponse, err := baseHttpClient.Client.Do(req)
	if err != nil {
		baseHttpClient.httpLog.Printf("Request failed: %v", err)
		return httpResponse, NewErrorHelper(NetworkError, "Request failed.", nil)
	}
	defer clientResponse.Body.Close()

	body, err := ioutil.ReadAll(clientResponse.Body)
	if err != nil {
		baseHttpClient.httpLog.Printf("Unable to read response: %v", err)
		return httpResponse, NewErrorHelper(DataError, "Error reading response.", nil)
	}

	httpResponse.Response = clientResponse
	httpResponse.Body = body
	if baseHttpClient.Debug {
		baseHttpClient.httpLog.Printf("%s %s -- %d %v", method, req.URL.RequestURI(), httpResponse.Response.StatusCode, req.Header)
	}

	return httpResponse, nil
}

func (baseHttpClient *BaseHttpClient) DoEnvelope(method, url string, params url.Values, headers http.Header, obj interface{}) error {
	resp, err := baseHttpClient.Do(method, url, params, headers)
	if err != nil {
		return err
	}

	err = readEnvelope(resp, obj)
	if err != nil {
		if _, ok := err.(Error); !ok {
			baseHttpClient.httpLog.Printf("Error parsing JSON response: %v", err)
		}
	}

	return err
}

func readEnvelope(resp HTTPResponse, obj interface{}) error {
	if resp.Response.StatusCode >= http.StatusBadRequest {
		var e HttpErrorEnvelope
		if err := json.Unmarshal(resp.Body, &e); err != nil {
			return NewErrorHelper(DataError, "Error parsing response.", nil)
		}
		return NewError(e.ErrorType, e.Message, resp.Response.StatusCode, e.Data)
	}
	successEnvl := HttpSuccessEnvelope{}
	successEnvl.Data = obj
	if err := json.Unmarshal(resp.Body, &successEnvl); err != nil {
		return NewErrorHelper(DataError, "Error parsing response.", nil)
	}
	return nil
}

func (baseHttpClient *BaseHttpClient) DoJSON(method, url string, params url.Values, headers http.Header, obj interface{}) (HTTPResponse, error) {
	resp, err := baseHttpClient.Do(method, url, params, headers)
	if err != nil {
		return resp, err
	}

	if err := json.Unmarshal(resp.Body, &obj); err != nil {
		baseHttpClient.httpLog.Printf("Error parsing JSON response: %v | %s", err, resp.Body)
		return resp, NewErrorHelper(DataError, "Error parsing response.", nil)
	}

	return resp, nil
}

func (baseHttpClient *BaseHttpClient) GetClient() *BaseHttpClient {
	return baseHttpClient
}
