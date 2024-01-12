package pkg

import (
	"fmt"
	"github.com/algotuners/zerodha-free-tier-go_sdk/pkg/constants"
	httpUtils2 "github.com/algotuners/zerodha-free-tier-go_sdk/pkg/httpUtils"
	"github.com/gocarina/gocsv"
	"github.com/google/go-querystring/query"
	"github.com/zerodha/gokiteconnect/v4/models"
	"net/http"
	"net/url"
	"time"
)

type quoteParams struct {
	Instruments []string `url:"i"`
}

type Quote map[string]struct {
	InstrumentToken   int          `json:"instrument_token"`
	Timestamp         models.Time  `json:"timestamp"`
	LastPrice         float64      `json:"last_price"`
	LastQuantity      int          `json:"last_quantity"`
	LastTradeTime     models.Time  `json:"last_trade_time"`
	AveragePrice      float64      `json:"average_price"`
	Volume            int          `json:"volume"`
	BuyQuantity       int          `json:"buy_quantity"`
	SellQuantity      int          `json:"sell_quantity"`
	OHLC              models.OHLC  `json:"ohlc"`
	NetChange         float64      `json:"net_change"`
	OI                float64      `json:"oi"`
	OIDayHigh         float64      `json:"oi_day_high"`
	OIDayLow          float64      `json:"oi_day_low"`
	LowerCircuitLimit float64      `json:"lower_circuit_limit"`
	UpperCircuitLimit float64      `json:"upper_circuit_limit"`
	Depth             models.Depth `json:"depth"`
}

type QuoteOHLC map[string]struct {
	InstrumentToken int         `json:"instrument_token"`
	LastPrice       float64     `json:"last_price"`
	OHLC            models.OHLC `json:"ohlc"`
}

type QuoteLTP map[string]struct {
	InstrumentToken int     `json:"instrument_token"`
	LastPrice       float64 `json:"last_price"`
}

type HistoricalData struct {
	Date   models.Time `json:"date"`
	Open   float64     `json:"open"`
	High   float64     `json:"high"`
	Low    float64     `json:"low"`
	Close  float64     `json:"close"`
	Volume int         `json:"volume"`
	OI     int         `json:"oi"`
}

type historicalDataReceived struct {
	Candles [][]interface{} `json:"candles"`
}

type historicalDataParams struct {
	FromDate        string `url:"from"`
	ToDate          string `url:"to"`
	Continuous      int    `url:"continuous"`
	OI              int    `url:"oi"`
	InstrumentToken int    `url:"instrument_token"`
	Interval        string `url:"interval"`
}

type Instrument struct {
	InstrumentToken int         `csv:"instrument_token"`
	ExchangeToken   int         `csv:"exchange_token"`
	Tradingsymbol   string      `csv:"tradingsymbol"`
	Name            string      `csv:"name"`
	LastPrice       float64     `csv:"last_price"`
	Expiry          models.Time `csv:"expiry"`
	StrikePrice     float64     `csv:"strike"`
	TickSize        float64     `csv:"tick_size"`
	LotSize         float64     `csv:"lot_size"`
	InstrumentType  string      `csv:"instrument_type"`
	Segment         string      `csv:"segment"`
	Exchange        string      `csv:"exchange"`
}

type Instruments []Instrument

var (
	maxDayLimitOnTimeFrame = map[string]int{
		"minute":   60,
		"5minute":  100,
		"15minute": 200,
		"60minute": 400,
		"day":      2000,
	}
)

func (kiteHttpClient *KiteHttpClient) GetQuote(instruments ...string) Quote {
	var (
		err     error
		quotes  Quote
		params  url.Values
		qParams quoteParams
	)

	qParams = quoteParams{
		Instruments: instruments,
	}

	if params, err = query.Values(qParams); err != nil {
		panic(httpUtils2.NewErrorHelper(httpUtils2.InputError, fmt.Sprintf("Error decoding order params: %v", err), nil))
	}

	err = kiteHttpClient.doEnvelope(http.MethodGet, constants.URIGetQuote, params, nil, &quotes)

	if err != nil {
		panic(err.Error())
	}
	return quotes
}

func (kiteHttpClient *KiteHttpClient) GetLTP(instruments ...string) QuoteLTP {
	var (
		err     error
		quotes  QuoteLTP
		params  url.Values
		qParams quoteParams
	)

	qParams = quoteParams{
		Instruments: instruments,
	}

	if params, err = query.Values(qParams); err != nil {
		panic(httpUtils2.NewErrorHelper(httpUtils2.InputError, fmt.Sprintf("Error decoding order params: %v", err), nil))
	}

	err = kiteHttpClient.doEnvelope(http.MethodGet, constants.URIGetQuote, params, nil, &quotes)
	if err != nil {
		panic(err.Error())
	}
	return quotes
}

func (kiteHttpClient *KiteHttpClient) GetOHLC(instruments ...string) QuoteOHLC {
	var (
		err     error
		quotes  QuoteOHLC
		params  url.Values
		qParams quoteParams
	)

	qParams = quoteParams{
		Instruments: instruments,
	}

	if params, err = query.Values(qParams); err != nil {
		panic(httpUtils2.NewErrorHelper(httpUtils2.InputError, fmt.Sprintf("Error decoding order params: %v", err), nil))
	}

	err = kiteHttpClient.doEnvelope(http.MethodGet, constants.URIGetQuote, params, nil, &quotes)
	if err != nil {
		panic(err.Error())
	}
	return quotes
}

func (kiteHttpClient *KiteHttpClient) formatHistoricalData(inp historicalDataReceived) []HistoricalData {
	var data []HistoricalData

	for _, i := range inp.Candles {
		var (
			ds     string
			open   float64
			high   float64
			low    float64
			close  float64
			volume int
			OI     int
			ok     bool
		)

		if ds, ok = i[0].(string); !ok {
			panic(httpUtils2.NewErrorHelper(httpUtils2.GeneralError, fmt.Sprintf("Error decoding response `date`: %v", i[0]), nil))
		}

		if open, ok = i[1].(float64); !ok {
			panic(httpUtils2.NewErrorHelper(httpUtils2.GeneralError, fmt.Sprintf("Error decoding response `open`: %v", i[1]), nil))
		}

		if high, ok = i[2].(float64); !ok {
			panic(httpUtils2.NewErrorHelper(httpUtils2.GeneralError, fmt.Sprintf("Error decoding response `high`: %v", i[2]), nil))
		}

		if low, ok = i[3].(float64); !ok {
			panic(httpUtils2.NewErrorHelper(httpUtils2.GeneralError, fmt.Sprintf("Error decoding response `low`: %v", i[3]), nil))
		}

		if close, ok = i[4].(float64); !ok {
			panic(httpUtils2.NewErrorHelper(httpUtils2.GeneralError, fmt.Sprintf("Error decoding response `close`: %v", i[4]), nil))
		}

		// Assert volume
		v, ok := i[5].(float64)
		if !ok {
			panic(httpUtils2.NewErrorHelper(httpUtils2.GeneralError, fmt.Sprintf("Error decoding response `volume`: %v", i[5]), nil))
		}

		volume = int(v)
		// Did we get OI?
		if len(i) > 6 {
			// Assert OI
			OIT, ok := i[6].(float64)
			if !ok {
				panic(httpUtils2.NewErrorHelper(httpUtils2.GeneralError, fmt.Sprintf("Error decoding response `oi`: %v", i[6]), nil))
			}
			OI = int(OIT)
		}

		// Parse string to date
		d, err := time.Parse("2006-01-02T15:04:05-0700", ds)
		if err != nil {
			panic(httpUtils2.NewErrorHelper(httpUtils2.GeneralError, fmt.Sprintf("Error decoding response: %v", err), nil))
		}

		data = append(data, HistoricalData{
			Date:   models.Time{d},
			Open:   open,
			High:   high,
			Low:    low,
			Close:  close,
			Volume: volume,
			OI:     OI,
		})
	}

	return data
}

func (kiteHttpClient *KiteHttpClient) GetHistoricalData(instrumentToken int, interval string, fromDate time.Time, toDate time.Time, continuous bool, OI bool) []HistoricalData {
	var (
		err       error
		params    url.Values
		inpParams historicalDataParams
	)

	inpParams.InstrumentToken = instrumentToken
	inpParams.Interval = interval
	inpParams.FromDate = fromDate.Format("2006-01-02 15:04:05")
	inpParams.ToDate = toDate.Format("2006-01-02 15:04:05")
	inpParams.Continuous = 0
	inpParams.OI = 0

	if continuous {
		inpParams.Continuous = 1
	}

	if OI {
		inpParams.OI = 1
	}

	if params, err = query.Values(inpParams); err != nil {
		panic(httpUtils2.NewErrorHelper(httpUtils2.InputError, fmt.Sprintf("Error decoding order params: %v", err), nil))
	}

	var resp historicalDataReceived
	if err := kiteHttpClient.doEnvelope(http.MethodGet, fmt.Sprintf(constants.URIGetHistorical, instrumentToken, interval), params, nil, &resp); err != nil {
		panic(err.Error())
	}

	return kiteHttpClient.formatHistoricalData(resp)
}

func (KiteHttpClient *KiteHttpClient) GetHistoricalDataV2(instrumentToken int, interval string, fromDate time.Time, toDate time.Time, continuous bool, OI bool) []HistoricalData {
	maxDays := maxDayLimitOnTimeFrame[interval]
	startDate := fromDate
	endDate := toDate
	var candleData []HistoricalData
	for startDate.Before(endDate) {
		apiLimitDate := endDate
		if startDate.Add(time.Duration(maxDays) * 24 * time.Hour).Before(endDate) {
			apiLimitDate = startDate.Add(time.Duration(maxDays) * 24 * time.Hour)
		}
		currentHistoricalData := KiteHttpClient.GetHistoricalData(instrumentToken, interval, startDate, apiLimitDate, false, false)
		candleData = append(candleData, currentHistoricalData...)
		startDate = apiLimitDate.AddDate(0, 0, 1)
		time.Sleep(time.Millisecond * 350)
	}
	return candleData
}

func (kiteHttpClient *KiteHttpClient) parseInstruments(data interface{}, url string, params url.Values) error {
	var (
		err  error
		resp httpUtils2.HTTPResponse
	)

	// Get CSV response
	if resp, err = kiteHttpClient.do(http.MethodGet, url, params, nil); err != nil {
		return err
	}

	// Unmarshal CSV response to instruments
	if err = gocsv.UnmarshalBytes(resp.Body, data); err != nil {
		return httpUtils2.NewErrorHelper(httpUtils2.GeneralError, fmt.Sprintf("Error parsing csv response: %v", err), nil)
	}

	return nil
}

func (kiteHttpClient *KiteHttpClient) GetInstruments() Instruments {
	var instruments Instruments
	err := kiteHttpClient.parseInstruments(&instruments, constants.URIGetInstruments, nil)
	if err != nil {
		panic(err.Error())
	}
	return instruments
}

func (kiteHttpClient *KiteHttpClient) GetInstrumentsByExchange(exchange string) Instruments {
	var instruments Instruments
	err := kiteHttpClient.parseInstruments(&instruments, fmt.Sprintf(constants.URIGetInstrumentsExchange, exchange), nil)
	if err != nil {
		panic(err.Error())
	}
	return instruments
}
