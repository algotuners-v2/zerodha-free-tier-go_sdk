package utils

import (
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"time"
)

func GenerateTOTP(secret string) (string, error) {
	otpCode, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", err
	}
	return otpCode, nil
}
