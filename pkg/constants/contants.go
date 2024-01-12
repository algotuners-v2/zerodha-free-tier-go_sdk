package constants

const (
	// Varieties
	VarietyRegular = "regular"
	VarietyAMO     = "amo"
	VarietyBO      = "bo"
	VarietyCO      = "co"
	VarietyIceberg = "iceberg"
	VarietyAuction = "auction"

	// Products
	ProductBO   = "BO"
	ProductCO   = "CO"
	ProductMIS  = "MIS"
	ProductCNC  = "CNC"
	ProductNRML = "NRML"

	// Order types
	OrderTypeMarket = "MARKET"
	OrderTypeLimit  = "LIMIT"
	OrderTypeSL     = "SL"
	OrderTypeSLM    = "SL-M"

	// Validities
	ValidityDay = "DAY"
	ValidityIOC = "IOC"
	ValidityTTL = "TTL"

	// Position Type
	PositionTypeDay       = "day"
	PositionTypeOvernight = "overnight"

	// Transaction type
	TransactionTypeBuy  = "BUY"
	TransactionTypeSell = "SELL"

	// Exchanges
	ExchangeNSE = "NSE"
	ExchangeBSE = "BSE"
	ExchangeMCX = "MCX"
	ExchangeNFO = "NFO"
	ExchangeBFO = "BFO"
	ExchangeCDS = "CDS"
	ExchangeBCD = "BCD"

	// Margins segments
	MarginsEquity    = "equity"
	MarginsCommodity = "commodity"

	// Order status
	OrderStatusComplete  = "COMPLETE"
	OrderStatusRejected  = "REJECTED"
	OrderStatusCancelled = "CANCELLED"
)
