package oneinch

import (
	"context"
	"fmt"
	"net/http"

	"github.com/vultisig/verifier/plugin/libhttp"
	"github.com/vultisig/vultisig-go/common"
)

type Client struct {
	baseURL string
	apiKey  string
}

func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
	}
}

type swapRequest struct {
	Chain        common.Chain
	Src          string
	Dst          string
	Amount       string
	From         string
	SlippagePerc int
}

type SwapResponse struct {
	ToAmount  string    `json:"toAmount"`
	Tx        TxData    `json:"tx"`
	FromToken TokenInfo `json:"fromToken"`
	ToToken   TokenInfo `json:"toToken"`
}

type TxData struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Data     string `json:"data"`
	Value    string `json:"value"`
	Gas      int64  `json:"gas"`
	GasPrice string `json:"gasPrice"`
}

type TokenInfo struct {
	Symbol   string `json:"symbol"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	Decimals int    `json:"decimals"`
}

func (c *Client) GetSwap(ctx context.Context, req swapRequest) (*SwapResponse, error) {
	chainID, err := req.Chain.EvmID()
	if err != nil {
		return nil, fmt.Errorf("failed to get chain ID: %w", err)
	}

	endpoint := fmt.Sprintf("%s/swap/%s/%d/swap", c.baseURL, APIVersion, chainID)

	params := map[string]string{
		"src":              req.Src,
		"dst":              req.Dst,
		"amount":           req.Amount,
		"from":             req.From,
		"slippage":         fmt.Sprintf("%d", req.SlippagePerc),
		"disableEstimate":  "true",
		"allowPartialFill": "false",
	}

	headers := map[string]string{
		"Authorization": "Bearer " + c.apiKey,
	}

	resp, err := libhttp.Call[SwapResponse](
		ctx,
		http.MethodGet,
		endpoint,
		headers,
		nil,
		params,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to call 1inch API: %w", err)
	}

	return &resp, nil
}
