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
	solana_swap "github.com/vultisig/app-recurring/internal/solana"
	"github.com/vultisig/app-recurring/internal/util"
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
	FeeAmount  string `json:"feeAmount,omitempty"`
	FeeMint    string `json:"feeMint,omitempty"`
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
	DynamicComputeUnitLimit       bool           `json:"dynamicComputeUnitLimit,omitempty"`
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

		accounts = append(accounts, solana.NewAccountMeta(pk, acc.IsWritable, acc.IsSigner))
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
	queryParams.Set("swapMode", "ExactIn")
	queryParams.Set("inputMint", inputMint)
	queryParams.Set("outputMint", outputMint)
	queryParams.Set("amount", amount.String())
	queryParams.Set("slippageBps", fmt.Sprintf("%d", slippageBps))
	// Restrict routes to fit within Solana's transaction size limit (1232 bytes) and default CU budget.
	// maxAccounts=30 is the recommended limit for legacy transactions without Address Lookup Tables.
	queryParams.Set("restrictIntermediateTokens", "true")
	queryParams.Set("maxAccounts", "30")

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
		UserPublicKey:           userPublicKey,
		QuoteResponse:           quote,
		WrapAndUnwrapSol:        true,
		UseSharedAccounts:       true,
		AsLegacyTransaction:     false,
		DynamicComputeUnitLimit: true,
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

// CheckSetup checks if setup transactions are needed
func (p *Provider) CheckSetup(ctx context.Context, from solana_swap.From, to solana_swap.To) (bool, error) {
	quote, err := p.GetQuote(
		ctx,
		util.IfEmptyElse(from.AssetID, solana.SolMint.String()),
		util.IfEmptyElse(to.AssetID, solana.SolMint.String()),
		from.Amount,
		DefaultSlippageBps,
	)
	if err != nil {
		return false, fmt.Errorf("failed to get quote: %w", err)
	}

	insts, err := p.GetSwapInstructions(ctx, quote, from.Address)
	if err != nil {
		return false, fmt.Errorf("failed to get swap instructions: %w", err)
	}

	return len(insts.SetupInstructions) > 0, nil
}

// BuildSetupTxs builds setup transactions that must be executed before the swap
func (p *Provider) BuildSetupTxs(ctx context.Context, from solana_swap.From, to solana_swap.To) ([][]byte, error) {
	quote, err := p.GetQuote(
		ctx,
		util.IfEmptyElse(from.AssetID, solana.SolMint.String()),
		util.IfEmptyElse(to.AssetID, solana.SolMint.String()),
		from.Amount,
		DefaultSlippageBps,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get quote: %w", err)
	}

	insts, err := p.GetSwapInstructions(ctx, quote, from.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to get swap instructions: %w", err)
	}

	if len(insts.SetupInstructions) == 0 {
		return nil, nil
	}

	block, err := p.rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent blockhash: %w", err)
	}

	feePayer, err := solana.PublicKeyFromBase58(from.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse fee payer address: %w", err)
	}

	setupTxs := make([][]byte, 0, len(insts.SetupInstructions))

	for i, setupInst := range insts.SetupInstructions {
		typedInst, err := setupInst.Typed()
		if err != nil {
			return nil, fmt.Errorf("failed to format setup instruction %d: %w", i, err)
		}

		requiredSigners := countRequiredSigners(setupInst)

		var ephemeralSigners []solana.PrivateKey
		txOptions := []solana.TransactionOption{solana.TransactionPayer(feePayer)}

		if requiredSigners > 1 {
			ephemeralCount := requiredSigners - 1
			ephemeralSigners = make([]solana.PrivateKey, ephemeralCount)

			for j := 0; j < ephemeralCount; j++ {
				ephemeralKey := solana.NewWallet()
				ephemeralSigners[j] = ephemeralKey.PrivateKey
			}
		}

		tx, err := solana.NewTransaction(
			[]solana.Instruction{typedInst},
			block.Value.Blockhash,
			txOptions...,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create setup transaction %d: %w", i, err)
		}

		for _, ephemeralSigner := range ephemeralSigners {
			_, signerErr := tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
				if key.Equals(ephemeralSigner.PublicKey()) {
					return &ephemeralSigner
				}
				return nil
			})
			if signerErr != nil {
				return nil, fmt.Errorf("failed to sign setup transaction %d with ephemeral signer: %w", i, signerErr)
			}
		}

		serializedTx, err := tx.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize setup transaction %d: %w", i, err)
		}

		setupTxs = append(setupTxs, serializedTx)
	}

	return setupTxs, nil
}

// MakeTx implements solana.Provider interface
// Note: Setup transactions should be executed via BuildSetupTxs before calling this
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

	feePayer, err := solana.PublicKeyFromBase58(from.Address)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse fee payer address: %w", err)
	}

	swapInst, err := insts.SwapInstruction.Typed()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to format swap instruction: %w", err)
	}

	requiredSigners := countRequiredSigners(insts.SwapInstruction)

	var ephemeralSigners []solana.PrivateKey
	txOptions := []solana.TransactionOption{solana.TransactionPayer(feePayer)}

	if requiredSigners > 1 {
		ephemeralCount := requiredSigners - 1
		ephemeralSigners = make([]solana.PrivateKey, ephemeralCount)

		for i := 0; i < ephemeralCount; i++ {
			ephemeralKey := solana.NewWallet()
			ephemeralSigners[i] = ephemeralKey.PrivateKey
		}
	}

	tx, err := solana.NewTransaction(
		[]solana.Instruction{swapInst},
		block.Value.Blockhash,
		txOptions...,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create transaction: %w", err)
	}

	for _, ephemeralSigner := range ephemeralSigners {
		_, signerErr := tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
			if key.Equals(ephemeralSigner.PublicKey()) {
				return &ephemeralSigner
			}
			return nil
		})
		if signerErr != nil {
			return nil, nil, fmt.Errorf("failed to sign with ephemeral signer: %w", signerErr)
		}
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

func countRequiredSigners(inst InstructionData) int {
	count := 0
	for _, acc := range inst.Accounts {
		if acc.IsSigner {
			count++
		}
	}
	return count
}

func (p *Provider) CheckCleanup(ctx context.Context, from solana_swap.From, to solana_swap.To) (bool, error) {
	quote, err := p.GetQuote(
		ctx,
		util.IfEmptyElse(from.AssetID, solana.SolMint.String()),
		util.IfEmptyElse(to.AssetID, solana.SolMint.String()),
		from.Amount,
		DefaultSlippageBps,
	)
	if err != nil {
		return false, fmt.Errorf("failed to get quote: %w", err)
	}

	insts, err := p.GetSwapInstructions(ctx, quote, from.Address)
	if err != nil {
		return false, fmt.Errorf("failed to get swap instructions: %w", err)
	}

	return insts.CleanupInstruction != nil, nil
}

func (p *Provider) BuildCleanupTxs(ctx context.Context, from solana_swap.From, to solana_swap.To) ([][]byte, error) {
	quote, err := p.GetQuote(
		ctx,
		util.IfEmptyElse(from.AssetID, solana.SolMint.String()),
		util.IfEmptyElse(to.AssetID, solana.SolMint.String()),
		from.Amount,
		DefaultSlippageBps,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get quote: %w", err)
	}

	insts, err := p.GetSwapInstructions(ctx, quote, from.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to get swap instructions: %w", err)
	}

	if insts.CleanupInstruction == nil {
		return nil, nil
	}

	block, err := p.rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent blockhash: %w", err)
	}

	feePayer, err := solana.PublicKeyFromBase58(from.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse fee payer address: %w", err)
	}

	cleanupInst, err := insts.CleanupInstruction.Typed()
	if err != nil {
		return nil, fmt.Errorf("failed to format cleanup instruction: %w", err)
	}

	tx, err := solana.NewTransaction(
		[]solana.Instruction{cleanupInst},
		block.Value.Blockhash,
		solana.TransactionPayer(feePayer),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create cleanup transaction: %w", err)
	}

	serializedTx, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize cleanup transaction: %w", err)
	}

	return [][]byte{serializedTx}, nil
}
