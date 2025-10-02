package jupiter

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/url"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	solana_swap "github.com/vultisig/dca/internal/solana"
	"github.com/vultisig/verifier/plugin/libhttp"
)

type Provider struct {
	apiURL    string
	rpcClient *rpc.Client
}

type QuoteRequest struct {
	InputMint                  string `json:"inputMint"`
	OutputMint                 string `json:"outputMint"`
	Amount                     string `json:"amount"`
	SlippageBps                int    `json:"slippageBps"`
	OnlyDirectRoutes           bool   `json:"onlyDirectRoutes,omitempty"`
	AsLegacyTransaction        bool   `json:"asLegacyTransaction,omitempty"`
	MaxAccounts                int    `json:"maxAccounts,omitempty"`
	MinimizeSlippage           bool   `json:"minimizeSlippage,omitempty"`
	RestrictIntermediateTokens bool   `json:"restrictIntermediateTokens,omitempty"`
}

type QuoteResponse struct {
	InputMint            string      `json:"inputMint"`
	InAmount             string      `json:"inAmount"`
	OutputMint           string      `json:"outputMint"`
	OutAmount            string      `json:"outAmount"`
	OtherAmountThreshold string      `json:"otherAmountThreshold"`
	SwapMode             string      `json:"swapMode"`
	SlippageBps          int         `json:"slippageBps"`
	PlatformFee          interface{} `json:"platformFee"`
	PriceImpactPct       string      `json:"priceImpactPct"`
	RoutePlan            []RoutePlan `json:"routePlan"`
	ContextSlot          int64       `json:"contextSlot"`
	TimeTaken            float64     `json:"timeTaken"`
}

type RoutePlan struct {
	SwapInfo SwapInfo `json:"swapInfo"`
	Percent  int      `json:"percent"`
}

type SwapInfo struct {
	AmmKey     string `json:"ammKey"`
	Label      string `json:"label"`
	InputMint  string `json:"inputMint"`
	OutputMint string `json:"outputMint"`
	InAmount   string `json:"inAmount"`
	OutAmount  string `json:"outAmount"`
	FeeAmount  string `json:"feeAmount"`
	FeeMint    string `json:"feeMint"`
}

type SwapRequest struct {
	UserPublicKey                 string         `json:"userPublicKey"`
	QuoteResponse                 QuoteResponse  `json:"quoteResponse"`
	WrapAndUnwrapSol              bool           `json:"wrapAndUnwrapSol,omitempty"`
	UseSharedAccounts             bool           `json:"useSharedAccounts,omitempty"`
	FeeAccount                    string         `json:"feeAccount,omitempty"`
	TrackingAccount               string         `json:"trackingAccount,omitempty"`
	ComputeUnitPriceMicroLamports *int           `json:"computeUnitPriceMicroLamports,omitempty"`
	PriorityLevelWithMaxLamports  map[string]int `json:"priorityLevelWithMaxLamports,omitempty"`
	AsLegacyTransaction           bool           `json:"asLegacyTransaction,omitempty"`
	UseTokenLedger                bool           `json:"useTokenLedger,omitempty"`
	DestinationTokenAccount       string         `json:"destinationTokenAccount,omitempty"`
}

type SwapInstructionsResponse struct {
	TokenLedgerInstruction      *string           `json:"tokenLedgerInstruction,omitempty"`
	ComputeBudgetInstructions   []InstructionData `json:"computeBudgetInstructions"`
	SetupInstructions           []InstructionData `json:"setupInstructions"`
	SwapInstruction             InstructionData   `json:"swapInstruction"`
	CleanupInstruction          *InstructionData  `json:"cleanupInstruction,omitempty"`
	AddressLookupTableAddresses []string          `json:"addressLookupTableAddresses"`
}

type InstructionData struct {
	ProgramId string   `json:"programId"`
	Accounts  []string `json:"accounts"`
	Data      string   `json:"data"`
}

func NewProvider(apiURL string, rpcClient *rpc.Client) *Provider {
	return &Provider{
		apiURL:    apiURL,
		rpcClient: rpcClient,
	}
}

func (p *Provider) GetQuote(
	ctx context.Context,
	inputMint, outputMint string,
	amount *big.Int,
	slippageBps int,
) (*QuoteResponse, error) {
	params := url.Values{}
	params.Add("inputMint", inputMint)
	params.Add("outputMint", outputMint)
	params.Add("amount", amount.String())
	params.Add("slippageBps", fmt.Sprintf("%d", slippageBps))

	url := fmt.Sprintf("%s/swap/v1/quote?%s", p.apiURL, params.Encode())

	resp, err := libhttp.Call[QuoteResponse](
		ctx,
		http.MethodGet,
		url,
		nil,
		nil,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get quote from Jupiter: %w", err)
	}

	return &resp, nil
}

func (p *Provider) GetSwapInstructions(
	ctx context.Context,
	quote QuoteResponse,
	userPublicKey string,
) (*SwapInstructionsResponse, error) {
	swapReq := SwapRequest{
		UserPublicKey:       userPublicKey,
		QuoteResponse:       quote,
		WrapAndUnwrapSol:    true,
		UseSharedAccounts:   true,
		AsLegacyTransaction: false,
	}

	url := fmt.Sprintf("%s/swap/v1/swap-instructions", p.apiURL)

	resp, err := libhttp.Call[SwapInstructionsResponse](
		ctx,
		http.MethodPost,
		url,
		nil,
		swapReq,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get swap instructions from Jupiter: %w", err)
	}

	return &resp, nil
}

// MakeTx implements solana.Provider interface
func (p *Provider) MakeTx(
	ctx context.Context,
	from solana_swap.From,
	to solana_swap.To,
) (*big.Int, []byte, error) {
	// Get quote
	quote, err := p.GetQuote(ctx, from.AssetID, to.AssetID, from.Amount, DefaultSlippageBps)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get quote: %w", err)
	}

	// Get swap instructions
	instructions, err := p.GetSwapInstructions(ctx, *quote, from.Address)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get swap instructions: %w", err)
	}

	// TODO parse insts

	// Serialize the transaction
	serializedTx, err := tx.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize transaction: %w", err)
	}

	// Parse output amount
	outAmount, ok := new(big.Int).SetString(quote.OutAmount, 10)
	if !ok {
		return nil, nil, fmt.Errorf("failed to parse out amount: %s", quote.OutAmount)
	}

	return outAmount, serializedTx, nil
}
