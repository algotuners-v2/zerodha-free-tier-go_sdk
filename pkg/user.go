package pkg

import (
	"crypto/sha256"
	"fmt"
	"github.com/algotuners/zerodha-sdk-go/pkg/constants"
	"github.com/algotuners/zerodha-sdk-go/pkg/models"
	"net/http"
	"net/url"
)

// UserSession represents the response after a successful authentication.
type UserSession struct {
	UserProfile
	UserSessionTokens

	UserID      string      `json:"user_id"`
	APIKey      string      `json:"api_key"`
	PublicToken string      `json:"public_token"`
	LoginTime   models.Time `json:"login_time"`
}

type UserSessionTokens struct {
	UserID       string `json:"user_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type UserMeta struct {
	DematConsent string `json:"demat_consent"`
}

type UserProfile struct {
	UserID        string   `json:"user_id"`
	UserName      string   `json:"user_name"`
	UserShortName string   `json:"user_shortname"`
	AvatarURL     string   `json:"avatar_url"`
	UserType      string   `json:"user_type"`
	Email         string   `json:"email"`
	Broker        string   `json:"broker"`
	Meta          UserMeta `json:"meta"`
	Products      []string `json:"products"`
	OrderTypes    []string `json:"order_types"`
	Exchanges     []string `json:"exchanges"`
}

func (kiteHttpClient *KiteHttpClient) GenerateSession(requestToken string, apiSecret string) (UserSession, error) {
	// Get SHA256 checksum
	h := sha256.New()
	h.Write([]byte(kiteHttpClient.apiKey + requestToken + apiSecret))

	// construct url values
	params := url.Values{}
	params.Add("api_key", kiteHttpClient.apiKey)
	params.Add("request_token", requestToken)
	params.Set("checksum", fmt.Sprintf("%x", h.Sum(nil)))

	var session UserSession
	err := kiteHttpClient.doEnvelope(http.MethodPost, constants.URIUserSession, params, nil, &session)

	// Set accessToken on successful session retrieve
	if err != nil && session.AccessToken != "" {
		kiteHttpClient.SetEncToken(session.AccessToken)
	}

	return session, err
}
