package jupiter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	solana_swap "github.com/vultisig/dca/internal/solana"
	"github.com/vultisig/dca/internal/util"
)

type Provider struct {
	apiURL    string
	headers   map[string]string
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

type Account struct {
	Pubkey     string `json:"pubkey"`
	IsSigner   bool   `json:"isSigner"`
	IsWritable bool   `json:"isWritable"`
}

type InstructionData struct {
	ProgramId string    `json:"programId"`
	Accounts  []Account `json:"accounts"`
	Data      string    `json:"data"`
}

// InstructionDataTyped implements solana.Instruction interface
type InstructionDataTyped struct {
	programID solana.PublicKey
	accounts  []*solana.AccountMeta
	data      []byte
}

func (i InstructionData) Typed() (InstructionDataTyped, error) {
	progr, err := solana.PublicKeyFromBase58(i.ProgramId)
	if err != nil {
		return InstructionDataTyped{}, fmt.Errorf("failed to get program id: %w", err)
	}

	accounts := make([]*solana.AccountMeta, 0, len(i.Accounts))
	for _, acc := range i.Accounts {
		pk, er := solana.PublicKeyFromBase58(acc.Pubkey)
		if er != nil {
			return InstructionDataTyped{}, fmt.Errorf("failed to get account: %w", er)
		}

		accounts = append(accounts, solana.NewAccountMeta(pk, acc.IsSigner, acc.IsWritable))
	}

	data, err := base64.StdEncoding.DecodeString(i.Data)
	if err != nil {
		return InstructionDataTyped{}, fmt.Errorf("failed to decode data: %w", err)
	}

	return InstructionDataTyped{
		programID: progr,
		accounts:  accounts,
		data:      data,
	}, nil
}

func (i InstructionDataTyped) ProgramID() solana.PublicKey {
	return i.programID
}

func (i InstructionDataTyped) Accounts() []*solana.AccountMeta {
	return i.accounts
}

func (i InstructionDataTyped) Data() ([]byte, error) {
	return i.data, nil
}

func NewProvider(apiURL string, rpcClient *rpc.Client) (*Provider, error) {
	return &Provider{
		apiURL:    apiURL,
		rpcClient: rpcClient,
		headers: map[string]string{
			"User-Agent": "vultisig-dca/1.0",
			"Accept":     "application/json",
		},
	}, nil
}

func (p *Provider) makeRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	fullURL := fmt.Sprintf("%s%s", p.apiURL, path)
	u, err := url.Parse(fullURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	var reqBody io.Reader
	if body != nil {
		jsonData, er := json.Marshal(body)
		if er != nil {
			return nil, fmt.Errorf("failed to marshal body: %w", er)
		}
		reqBody = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	parsedURL, err := url.Parse(p.apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse api url: %w", err)
	}
	req.Host = parsedURL.Host

	for k, v := range p.headers {
		req.Header.Set(k, v)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make http call: %w", err)
	}
	defer func() {
		_ = res.Body.Close()
	}()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get successful response: status_code: %d, res_body: %s", res.StatusCode, string(bodyBytes))
	}

	return bodyBytes, nil
}

func (p *Provider) GetQuote(
	ctx context.Context,
	inputMint, outputMint string,
	amount *big.Int,
	slippageBps int,
) (QuoteResponse, error) {
	queryParams := url.Values{}
	queryParams.Set("inputMint", inputMint)
	queryParams.Set("outputMint", outputMint)
	queryParams.Set("amount", amount.String())
	queryParams.Set("slippageBps", fmt.Sprintf("%d", slippageBps))

	path := fmt.Sprintf("/swap/v1/quote?%s", queryParams.Encode())

	bodyBytes, err := p.makeRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return QuoteResponse{}, fmt.Errorf("failed to get quote from Jupiter: %w", err)
	}

	var resp QuoteResponse
	err = json.Unmarshal(bodyBytes, &resp)
	if err != nil {
		return QuoteResponse{}, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return resp, nil
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

	bodyBytes, err := p.makeRequest(ctx, http.MethodPost, "/swap/v1/swap-instructions", swapReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get swap instructions from Jupiter: %w", err)
	}

	var resp SwapInstructionsResponse
	err = json.Unmarshal(bodyBytes, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &resp, nil
}

// MakeTx implements solana.Provider interface
func (p *Provider) MakeTx(
	ctx context.Context,
	from solana_swap.From,
	to solana_swap.To,
) (*big.Int, []byte, error) {
	quote, err := p.GetQuote(
		ctx,
		util.IfEmptyElse(from.AssetID, solana.SolMint.String()),
		util.IfEmptyElse(to.AssetID, solana.SolMint.String()),
		from.Amount,
		DefaultSlippageBps,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get quote: %w", err)
	}

	insts, err := p.GetSwapInstructions(ctx, quote, from.Address)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get swap instructions: %w", err)
	}

	block, err := p.rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get recent blockhash: %w", err)
	}

	inst, err := insts.SwapInstruction.Typed()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to format swap instruction: %w", err)
	}

	tx, err := solana.NewTransaction(
		[]solana.Instruction{inst},
		block.Value.Blockhash,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create transaction: %w", err)
	}

	serializedTx, err := tx.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize transaction: %w", err)
	}

	outAmount, ok := new(big.Int).SetString(quote.OutAmount, 10)
	if !ok {
		return nil, nil, fmt.Errorf("failed to parse out amount: %s", quote.OutAmount)
	}

	return outAmount, serializedTx, nil
}
