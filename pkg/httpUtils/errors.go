package httpUtils

import "net/http"

const (
	GeneralError    = "GeneralException"
	TokenError      = "TokenException"
	PermissionError = "PermissionError"
	UserError       = "UserException"
	TwoFAError      = "TwoFAException"
	OrderError      = "OrderException"
	InputError      = "InputException"
	DataError       = "DataException"
	NetworkError    = "NetworkException"
)

type Error struct {
	Code      int
	ErrorType string
	Message   string
	Data      interface{}
}

func (e Error) Error() string {
	return e.Message
}

func NewErrorHelper(etype string, message string, data interface{}) error {
	var (
		code = http.StatusInternalServerError
	)

	switch etype {
	case GeneralError:
		code = http.StatusInternalServerError
	case TokenError:
		code = http.StatusForbidden
	case PermissionError:
		code = http.StatusForbidden
	case UserError:
		code = http.StatusForbidden
	case TwoFAError:
		code = http.StatusForbidden
	case OrderError:
		code = http.StatusBadRequest
	case InputError:
		code = http.StatusBadRequest
	case DataError:
		code = http.StatusGatewayTimeout
	case NetworkError:
		code = http.StatusServiceUnavailable
	default:
		code = http.StatusInternalServerError
		etype = GeneralError
	}

	return NewError(etype, message, code, data)
}

func NewError(etype, message string, code int, data interface{}) Error {
	return Error{
		Message:   message,
		ErrorType: etype,
		Data:      data,
		Code:      code,
	}
}

func GetErrorName(code int) string {
	var err string

	switch code {
	case http.StatusInternalServerError:
		err = GeneralError
	case http.StatusForbidden, http.StatusUnauthorized:
		err = TokenError
	case http.StatusBadRequest:
		err = InputError
	case http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		err = NetworkError
	default:
		err = GeneralError
	}

	return err
}
