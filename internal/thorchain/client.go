package thorchain

import (
	"context"
	"fmt"
	"net/http"

	"github.com/vultisig/verifier/plugin/libhttp"
)

type Client struct {
	baseURL string
}

func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
	}
}

type quoteSwapRequest struct {
	FromAsset             string `url:"from_asset"`
	ToAsset               string `url:"to_asset"`
	Amount                string `url:"amount"`
	Destination           string `url:"destination,omitempty"`
	RefundAddress         string `url:"refund_address,omitempty"`
	StreamingInterval     string `url:"streaming_interval,omitempty"`
	StreamingQuantity     string `url:"streaming_quantity,omitempty"`
	ToleranceBps          string `url:"tolerance_bps,omitempty"`
	LiquidityToleranceBps string `url:"liquidity_tolerance_bps,omitempty"`
	AffiliateBps          string `url:"affiliate_bps,omitempty"`
	Affiliate             string `url:"affiliate,omitempty"`
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

type inboundAddressesRequest struct {
	Height string `url:"height,omitempty"`
}

type inboundAddressesResponse []inboundAddress

type inboundAddress struct {
	Chain                thorNetwork `json:"chain"`
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

func (c *Client) getQuote(
	ctx context.Context,
	req quoteSwapRequest,
) (quoteSwapResponse, error) {
	params := map[string]string{
		"from_asset": req.FromAsset,
		"to_asset":   req.ToAsset,
		"amount":     req.Amount,
	}

	if req.Destination != "" {
		params["destination"] = req.Destination
	}
	if req.RefundAddress != "" {
		params["refund_address"] = req.RefundAddress
	}
	if req.StreamingInterval != "" {
		params["streaming_interval"] = req.StreamingInterval
	}
	if req.StreamingQuantity != "" {
		params["streaming_quantity"] = req.StreamingQuantity
	}
	if req.ToleranceBps != "" {
		params["tolerance_bps"] = req.ToleranceBps
	}
	if req.LiquidityToleranceBps != "" {
		params["liquidity_tolerance_bps"] = req.LiquidityToleranceBps
	}
	if req.AffiliateBps != "" {
		params["affiliate_bps"] = req.AffiliateBps
	}
	if req.Affiliate != "" {
		params["affiliate"] = req.Affiliate
	}

	resp, err := libhttp.Call[quoteSwapResponse](
		ctx,
		http.MethodGet,
		c.baseURL+"/thorchain/quote/swap",
		nil,
		nil,
		params,
	)
	if err != nil {
		return quoteSwapResponse{}, fmt.Errorf("failed to get quote: %w", err)
	}

	return resp, nil
}

func (c *Client) getInboundAddresses(
	ctx context.Context,
	req inboundAddressesRequest,
) (inboundAddressesResponse, error) {
	params := map[string]string{}

	if req.Height != "" {
		params["height"] = req.Height
	}

	resp, err := libhttp.Call[inboundAddressesResponse](
		ctx,
		http.MethodGet,
		c.baseURL+"/thorchain/inbound_addresses",
		nil,
		nil,
		params,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get inbound addresses: %w", err)
	}

	return resp, nil
}
