package pkg

import (
	"fmt"
	"github.com/algotuners-v2/zerodha-free-tier-go_sdk/pkg/constants"
	"github.com/algotuners-v2/zerodha-free-tier-go_sdk/pkg/httpUtils"
	"github.com/google/go-querystring/query"
	"github.com/zerodha/gokiteconnect/v4/models"
	"net/http"
	"net/url"
)

type Order struct {
	AccountID string `json:"account_id"`
	PlacedBy  string `json:"placed_by"`

	OrderID                 string                 `json:"order_id"`
	ExchangeOrderID         string                 `json:"exchange_order_id"`
	ParentOrderID           string                 `json:"parent_order_id"`
	Status                  string                 `json:"status"`
	StatusMessage           string                 `json:"status_message"`
	StatusMessageRaw        string                 `json:"status_message_raw"`
	OrderTimestamp          models.Time            `json:"order_timestamp"`
	ExchangeUpdateTimestamp models.Time            `json:"exchange_update_timestamp"`
	ExchangeTimestamp       models.Time            `json:"exchange_timestamp"`
	Variety                 string                 `json:"variety"`
	Modified                bool                   `json:"modified"`
	Meta                    map[string]interface{} `json:"meta"`

	Exchange        string `json:"exchange"`
	TradingSymbol   string `json:"tradingsymbol"`
	InstrumentToken uint32 `json:"instrument_token"`

	OrderType         string  `json:"order_type"`
	TransactionType   string  `json:"transaction_type"`
	Validity          string  `json:"validity"`
	ValidityTTL       int     `json:"validity_ttl"`
	Product           string  `json:"product"`
	Quantity          float64 `json:"quantity"`
	DisclosedQuantity float64 `json:"disclosed_quantity"`
	Price             float64 `json:"price"`
	TriggerPrice      float64 `json:"trigger_price"`

	AveragePrice      float64 `json:"average_price"`
	FilledQuantity    float64 `json:"filled_quantity"`
	PendingQuantity   float64 `json:"pending_quantity"`
	CancelledQuantity float64 `json:"cancelled_quantity"`

	AuctionNumber string `json:"auction_number"`

	Tag  string   `json:"tag"`
	Tags []string `json:"tags"`
}

type Orders []Order

type OrderParams struct {
	Exchange        string `url:"exchange,omitempty"`
	Tradingsymbol   string `url:"tradingsymbol,omitempty"`
	Validity        string `url:"validity,omitempty"`
	ValidityTTL     int    `url:"validity_ttl,omitempty"`
	Product         string `url:"product,omitempty"`
	OrderType       string `url:"order_type,omitempty"`
	TransactionType string `url:"transaction_type,omitempty"`

	Quantity          int     `url:"quantity,omitempty"`
	DisclosedQuantity int     `url:"disclosed_quantity,omitempty"`
	Price             float64 `url:"price,omitempty"`
	TriggerPrice      float64 `url:"trigger_price,omitempty"`

	Squareoff        float64 `url:"squareoff,omitempty"`
	Stoploss         float64 `url:"stoploss,omitempty"`
	TrailingStoploss float64 `url:"trailing_stoploss,omitempty"`

	IcebergLegs int `url:"iceberg_legs,omitempty"`
	IcebergQty  int `url:"iceberg_quantity,omitempty"`

	AuctionNumber string `url:"auction_number,omitempty"`

	Tag string `json:"tag" url:"tag,omitempty"`
}

type OrderResponse struct {
	OrderID string `json:"order_id"`
}

type Trade struct {
	AveragePrice      float64     `json:"average_price"`
	Quantity          float64     `json:"quantity"`
	TradeID           string      `json:"trade_id"`
	Product           string      `json:"product"`
	FillTimestamp     models.Time `json:"fill_timestamp"`
	ExchangeTimestamp models.Time `json:"exchange_timestamp"`
	ExchangeOrderID   string      `json:"exchange_order_id"`
	OrderID           string      `json:"order_id"`
	TransactionType   string      `json:"transaction_type"`
	TradingSymbol     string      `json:"tradingsymbol"`
	Exchange          string      `json:"exchange"`
	InstrumentToken   uint32      `json:"instrument_token"`
}

type Trades []Trade

func (kiteHttpClient *KiteHttpClient) GetOrders() Orders {
	var orders Orders
	err := kiteHttpClient.doEnvelope(http.MethodGet, constants.URIGetOrders, nil, nil, &orders)
	if err != nil {
		panic(err.Error())
	}
	return orders
}

func (kiteHttpClient *KiteHttpClient) GetTrades() Trades {
	var trades Trades
	err := kiteHttpClient.doEnvelope(http.MethodGet, constants.URIGetTrades, nil, nil, &trades)
	if err != nil {
		panic(err.Error())
	}
	return trades
}

func (kiteHttpClient *KiteHttpClient) GetOrderHistory(OrderID string) []Order {
	var orderHistory []Order
	err := kiteHttpClient.doEnvelope(http.MethodGet, fmt.Sprintf(constants.URIGetOrderHistory, OrderID), nil, nil, &orderHistory)
	if err != nil {
		panic(err.Error())
	}
	return orderHistory
}

func (kiteHttpClient *KiteHttpClient) GetOrderTrades(OrderID string) []Trade {
	var orderTrades []Trade
	err := kiteHttpClient.doEnvelope(http.MethodGet, fmt.Sprintf(constants.URIGetOrderTrades, OrderID), nil, nil, &orderTrades)
	if err != nil {
		panic(err.Error())
	}
	return orderTrades
}

func (kiteHttpClient *KiteHttpClient) PlaceOrder(variety string, orderParams OrderParams) OrderResponse {
	var (
		orderResponse OrderResponse
		params        url.Values
		err           error
	)

	if params, err = query.Values(orderParams); err != nil {
		panic(httpUtils.NewErrorHelper(httpUtils.InputError, fmt.Sprintf("Error decoding order params: %v", err), nil))
	}

	err = kiteHttpClient.doEnvelope(http.MethodPost, fmt.Sprintf(constants.URIPlaceOrder, variety), params, nil, &orderResponse)
	if err != nil {
		panic(err.Error())
	}
	return orderResponse
}

func (kiteHttpClient *KiteHttpClient) ModifyOrder(variety string, orderID string, orderParams OrderParams) OrderResponse {
	var (
		orderResponse OrderResponse
		params        url.Values
		err           error
	)

	if params, err = query.Values(orderParams); err != nil {
		panic(httpUtils.NewErrorHelper(httpUtils.InputError, fmt.Sprintf("Error decoding order params: %v", err), nil))
	}

	err = kiteHttpClient.doEnvelope(http.MethodPut, fmt.Sprintf(constants.URIModifyOrder, variety, orderID), params, nil, &orderResponse)
	if err != nil {
		panic(err.Error())
	}
	return orderResponse
}

func (kiteHttpClient *KiteHttpClient) CancelOrder(variety string, orderID string, parentOrderID *string) OrderResponse {
	var (
		orderResponse OrderResponse
		params        url.Values
	)

	if parentOrderID != nil {
		// initialize the params map first
		params := url.Values{}
		params.Add("parent_order_id", *parentOrderID)
	}

	err := kiteHttpClient.doEnvelope(http.MethodDelete, fmt.Sprintf(constants.URICancelOrder, variety, orderID), params, nil, &orderResponse)
	if err != nil {
		panic(err.Error())
	}
	return orderResponse
}

func (kiteHttpClient *KiteHttpClient) ExitOrder(variety string, orderID string, parentOrderID *string) OrderResponse {
	return kiteHttpClient.CancelOrder(variety, orderID, parentOrderID)
}
