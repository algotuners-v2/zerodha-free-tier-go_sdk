package constants

const (
	URIUserSession           string = "/session/token"
	URIUserSessionInvalidate string = "/session/token"
	URIUserSessionRenew      string = "/session/refresh_token"
	URIUserProfile           string = "/user/profile"
	URIUserMargins           string = "/user/margins"
	URIUserMarginsSegment    string = "/user/margins/%s" // "/user/margins/{segment}"

	URIGetOrders       string = "/orders"
	URIGetTrades       string = "/trades"
	URIGetOrderHistory string = "/orders/%s"        // "/orders/{order_id}"
	URIGetOrderTrades  string = "/orders/%s/trades" // "/orders/{order_id}/trades"
	URIPlaceOrder      string = "/orders/%s"        // "/orders/{variety}"
	URIModifyOrder     string = "/orders/%s/%s"     // "/orders/{variety}/{order_id}"
	URICancelOrder     string = "/orders/%s/%s"     // "/orders/{variety}/{order_id}"

	URIGetPositions       string = "/portfolio/positions"
	URIGetHoldings        string = "/portfolio/holdings"
	URIInitHoldingsAuth   string = "/portfolio/holdings/authorise"
	URIAuctionInstruments string = "/portfolio/holdings/auctions"
	URIConvertPosition    string = "/portfolio/positions"

	URIOrderMargins  string = "/margins/orders"
	URIBasketMargins string = "/margins/basket"

	// MF endpoints
	URIGetMFOrders      string = "/mf/orders"
	URIGetMFOrderInfo   string = "/mf/orders/%s" // "/mf/orders/{order_id}"
	URIPlaceMFOrder     string = "/mf/orders"
	URICancelMFOrder    string = "/mf/orders/%s" // "/mf/orders/{order_id}"
	URIGetMFSIPs        string = "/mf/sips"
	URIGetMFSIPInfo     string = "/mf/sips/%s" //  "/mf/sips/{sip_id}"
	URIPlaceMFSIP       string = "/mf/sips"
	URIModifyMFSIP      string = "/mf/sips/%s" //  "/mf/sips/{sip_id}"
	URICancelMFSIP      string = "/mf/sips/%s" //  "/mf/sips/{sip_id}"
	URIGetMFHoldings    string = "/mf/holdings"
	URIGetMFHoldingInfo string = "/mf/holdings/%s" //  "/mf/holdings/{isin}"
	URIGetAllotedISINs  string = "/mf/allotments"

	// GTT endpoints
	URIPlaceGTT  string = "/gtt/triggers"
	URIGetGTTs   string = "/gtt/triggers"
	URIGetGTT    string = "/gtt/triggers/%d"
	URIModifyGTT string = "/gtt/triggers/%d"
	URIDeleteGTT string = "/gtt/triggers/%d"

	URIGetInstruments         string = "/instruments"
	URIGetMFInstruments       string = "/mf/instruments"
	URIGetInstrumentsExchange string = "/instruments/%s"                  // "/instruments/{exchange}"
	URIGetHistorical          string = "/instruments/historical/%d/%s"    // "/instruments/historical/{instrument_token}/{interval}"
	URIGetTriggerRange        string = "/instruments/%s/%s/trigger_range" // "/instruments/{exchange}/{tradingsymbol}/trigger_range"

	URIGetQuote string = "/quote"
	URIGetLTP   string = "/quote/ltp"
	URIGetOHLC  string = "/quote/ohlc"
)
