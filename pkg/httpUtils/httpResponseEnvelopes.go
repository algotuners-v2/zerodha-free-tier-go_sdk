package httpUtils

type HttpErrorEnvelope struct {
	Status    string      `json:"status"`
	ErrorType string      `json:"error_type"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data"`
}

type HttpSuccessEnvelope struct {
	Data interface{} `json:"data"`
}

type HttpsPlainResponse struct {
	Code    int    `json:"code"`
	Message string `json:"string"`
}
