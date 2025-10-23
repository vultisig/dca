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
}

func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
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
	DstAmount string `json:"dstAmount"`
	Tx        TxData `json:"tx"`
}

type TxData struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Data     string `json:"data"`
	Value    string `json:"value"`
	Gas      int64  `json:"gas"`
	GasPrice string `json:"gasPrice"`
}

type SpenderResponse struct {
	Address string `json:"address"`
}

func (c *Client) GetSpender(ctx context.Context, chain common.Chain) (string, error) {
	chainID, err := chain.EvmID()
	if err != nil {
		return "", fmt.Errorf("failed to get chain ID: %w", err)
	}

	endpoint := fmt.Sprintf("%s/swap/%s/%d/approve/spender", c.baseURL, APIVersion, chainID)

	resp, err := libhttp.Call[SpenderResponse](
		ctx,
		http.MethodGet,
		endpoint,
		nil,
		nil,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to get spender address: %w", err)
	}

	return resp.Address, nil
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
		"compatibility":    "true",
	}

	resp, err := libhttp.Call[SwapResponse](
		ctx,
		http.MethodGet,
		endpoint,
		nil,
		nil,
		params,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to call 1inch API: %w", err)
	}

	return &resp, nil
}
