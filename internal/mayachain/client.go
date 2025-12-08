package mayachain

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/vultisig/verifier/plugin/libhttp"
)

// Client handles MayaChain API interactions
type Client struct {
	baseURL string
}

// NewClient creates a new MayaChain client
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
	}
}

type quoteSwapRequest struct {
	FromAsset             string `json:"from_asset"`
	ToAsset               string `json:"to_asset"`
	Amount                string `json:"amount"`
	Destination           string `json:"destination,omitempty"`
	RefundAddress         string `json:"refund_address,omitempty"`
	StreamingInterval     string `json:"streaming_interval,omitempty"`
	StreamingQuantity     string `json:"streaming_quantity,omitempty"`
	ToleranceBps          string `json:"tolerance_bps,omitempty"`
	LiquidityToleranceBps string `json:"liquidity_tolerance_bps,omitempty"`
	AffiliateBps          string `json:"affiliate_bps,omitempty"`
	Affiliate             string `json:"affiliate,omitempty"`
}

type quoteSwapResponse struct {
	InboundAddress             string    `json:"inbound_address"`
	InboundConfirmationBlocks  int64     `json:"inbound_confirmation_blocks"`
	InboundConfirmationSeconds int64     `json:"inbound_confirmation_seconds"`
	OutboundDelayBlocks        int64     `json:"outbound_delay_blocks"`
	OutboundDelaySeconds       int64     `json:"outbound_delay_seconds"`
	Fees                       quoteFees `json:"fees"`
	Router                     string    `json:"router"`
	Expiry                     int64     `json:"expiry"`
	Warning                    string    `json:"warning"`
	Notes                      string    `json:"notes"`
	DustThreshold              string    `json:"dust_threshold"`
	RecommendedMinAmountIn     string    `json:"recommended_min_amount_in"`
	Memo                       string    `json:"memo"`
	ExpectedAmountOut          string    `json:"expected_amount_out"`
	ExpectedAmountOutStreaming string    `json:"expected_amount_out_streaming"`
	MaxStreamingQuantity       int64     `json:"max_streaming_quantity"`
	StreamingSwapBlocks        int64     `json:"streaming_swap_blocks"`
	StreamingSwapSeconds       int64     `json:"streaming_swap_seconds"`
	TotalSwapSeconds           int64     `json:"total_swap_seconds"`
}

type quoteFees struct {
	Asset       string `json:"asset"`
	Affiliate   string `json:"affiliate"`
	Outbound    string `json:"outbound"`
	Liquidity   string `json:"liquidity"`
	Total       string `json:"total"`
	SlippageBps int64  `json:"slippage_bps"`
	TotalBps    int64  `json:"total_bps"`
}

type inboundAddressesResponse []inboundAddress

type inboundAddress struct {
	Chain                mayaNetwork `json:"chain"`
	PubKey               string      `json:"pub_key"`
	Address              string      `json:"address"`
	Router               string      `json:"router"`
	Halted               bool        `json:"halted"`
	GlobalTradingPaused  bool        `json:"global_trading_paused"`
	ChainTradingPaused   bool        `json:"chain_trading_paused"`
	ChainLpActionsPaused bool        `json:"chain_lp_actions_paused"`
	GasRate              string      `json:"gas_rate"`
	GasRateUnits         string      `json:"gas_rate_units"`
	OutboundTxSize       string      `json:"outbound_tx_size"`
	OutboundFee          string      `json:"outbound_fee"`
	DustThreshold        string      `json:"dust_threshold"`
}

type poolsResponse []pool

type pool struct {
	Asset               string `json:"asset"`
	ShortCode           string `json:"short_code"`
	Status              string `json:"status"`
	Decimals            int    `json:"decimals"`
	PendingInboundAsset string `json:"pending_inbound_asset"`
	PendingInboundCacao string `json:"pending_inbound_cacao"`
	BalanceAsset        string `json:"balance_asset"`
	BalanceCacao        string `json:"balance_cacao"`
	PoolUnits           string `json:"pool_units"`
	LPUnits             string `json:"lp_units"`
	SynthUnits          string `json:"synth_units"`
	SynthSupply         string `json:"synth_supply"`
	SaversDepth         string `json:"savers_depth"`
	SaversUnits         string `json:"savers_units"`
}

func (c *Client) getQuote(
	ctx context.Context,
	req quoteSwapRequest,
) (quoteSwapResponse, error) {
	params, err := structToParams(req)
	if err != nil {
		return quoteSwapResponse{}, fmt.Errorf("failed to convert request to params: %w", err)
	}

	resp, err := libhttp.Call[quoteSwapResponse](
		ctx,
		http.MethodGet,
		c.baseURL+"/mayachain/quote/swap",
		nil,
		nil,
		params,
	)
	if err != nil {
		return quoteSwapResponse{}, fmt.Errorf("failed to get quote: %w", err)
	}

	return resp, nil
}

func (c *Client) getInboundAddresses(ctx context.Context) (inboundAddressesResponse, error) {
	resp, err := libhttp.Call[inboundAddressesResponse](
		ctx,
		http.MethodGet,
		c.baseURL+"/mayachain/inbound_addresses",
		nil,
		nil,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get inbound addresses: %w", err)
	}

	return resp, nil
}

func (c *Client) getPools(ctx context.Context) (poolsResponse, error) {
	resp, err := libhttp.Call[poolsResponse](
		ctx,
		http.MethodGet,
		c.baseURL+"/mayachain/pools",
		nil,
		nil,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get pools: %w", err)
	}

	return resp, nil
}

func structToParams(v interface{}) (map[string]string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal struct: %w", err)
	}

	var jsonMap map[string]interface{}
	if err := json.Unmarshal(data, &jsonMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to map: %w", err)
	}

	params := make(map[string]string)
	for key, value := range jsonMap {
		if value != nil {
			if strValue, ok := value.(string); ok && strValue != "" {
				params[key] = strValue
			}
		}
	}

	return params, nil
}
