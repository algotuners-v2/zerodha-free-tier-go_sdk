package constants

import "time"

const (
	Name              string        = "gokiteconnect"
	Version           string        = "4.0.2"
	RequestTimeout    time.Duration = 7000 * time.Millisecond
	BaseURI           string        = "https://api.kite.trade"
	KiteBaseURI       string        = "https://kite.zerodha.com"
	KiteHeaderVersion string        = "3"
)
