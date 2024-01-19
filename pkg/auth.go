package pkg

import (
	"fmt"
	"github.com/algotuners-v2/zerodha-free-tier-go_sdk/pkg/httpUtils"
	"github.com/algotuners-v2/zerodha-free-tier-go_sdk/pkg/utils"
	"net/http"
	"net/url"
	"strings"
)

type FreeTierKiteLogin struct {
	EncToken string
}

const (
	ZerodhaQuoteRoute            = "https://api.kite.trade/quote"
	ZerodhaLoginRoute            = "https://kite.zerodha.com/api/login"
	ZerodhaTwofaRoute            = "https://kite.zerodha.com/api/twofa"
	queryParamForTestingQuoteApi = "i=NSE:INFY"
)

func (ftkl *FreeTierKiteLogin) GetEncToken(clientId string, password string, totpCode string) (string, error) {
	fmt.Println("Fetching zerodha ENC token from login")
	loginData := url.Values{}
	loginData.Set("user_id", clientId)
	loginData.Set("password", password)
	session := &http.Client{}
	loginResponse, err := session.Post(ZerodhaLoginRoute, "application/x-www-form-urlencoded", strings.NewReader(loginData.Encode()))
	if err != nil {
		fmt.Println("Fetching zerodha ENC token from login")
		return "", err
	}
	defer loginResponse.Body.Close()
	if loginResponse.StatusCode == http.StatusOK {
		var loginResponseData map[string]interface{}
		err = utils.DeserializeJSON(loginResponse.Body, &loginResponseData)
		if err != nil {
			return "", err
		}
		requestID, _ := loginResponseData["data"].(map[string]interface{})["request_id"].(string)
		twofaData := url.Values{}
		totp, totpErr := utils.GenerateTOTP(totpCode)
		if totpErr != nil {
			fmt.Println(totpErr.Error())
			return "", totpErr
		}
		twofaData.Set("user_id", clientId)
		twofaData.Set("request_id", requestID)
		twofaData.Set("twofa_value", totp)
		twofaData.Set("twofa_type", "totp")
		twofaData.Set("skip_session", "")
		twofaResponse, twofaErr := session.Post(ZerodhaTwofaRoute, "application/x-www-form-urlencoded", strings.NewReader(twofaData.Encode()))
		if twofaErr != nil {
			return "", twofaErr
		}
		defer twofaResponse.Body.Close()
		if twofaResponse.StatusCode == http.StatusOK {
			encToken, cookieErr := ftkl.GetCookieValue(twofaResponse, "enctoken")
			if cookieErr != nil {
				return "", cookieErr
			}
			return encToken, nil
		} else {
			return "", fmt.Errorf("Two-Factor Authentication request failed with status code %d: %s", twofaResponse.StatusCode, twofaResponse.Body)
		}
	} else {
		return "", fmt.Errorf("login request failed with status code %d: %s", loginResponse.StatusCode, loginResponse.Body)
	}
}

func (ftkl *FreeTierKiteLogin) IsEncTokenValid(encToken string) (bool, error) {
	client := &http.Client{}
	httpClient := httpUtils.GenerateHttpClient(client, false)
	queryParams := []byte(queryParamForTestingQuoteApi)
	headers := ftkl.GetZerodhaAuthHeaders(encToken, nil)
	response, err := httpClient.DoRaw(http.MethodGet, ZerodhaQuoteRoute, queryParams, headers)
	if err != nil {
		return false, err
	}
	defer response.Response.Body.Close()
	return response.Response.StatusCode == http.StatusOK, nil
}

func (ftkl *FreeTierKiteLogin) GetZerodhaAuthHeaders(authToken string, headers http.Header) http.Header {
	if headers == nil {
		headers = map[string][]string{}
	}
	headers.Add("Authorization", "enctoken "+authToken)
	return headers
}

func (ftkl *FreeTierKiteLogin) GetCookieValue(resp *http.Response, cookieName string) (string, error) {
	cookies := resp.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == cookieName {
			return cookie.Value, nil
		}
	}
	return "", fmt.Errorf("cookie not found: %s", cookieName)
}
