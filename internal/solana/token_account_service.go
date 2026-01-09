package solana

import (
	"context"
	"errors"
	"fmt"
	"strings"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
)

type tokenAccountService struct {
	rpcClient *rpc.Client
}

func newTokenAccountService(rpcClient *rpc.Client) *tokenAccountService {
	return &tokenAccountService{
		rpcClient: rpcClient,
	}
}

// GetTokenProgram queries the mint account to determine which token program owns it and the token decimals.
// Returns TokenProgramID for legacy SPL tokens or Token2022ProgramID for Token-2022 tokens, plus decimals.
// Token-2022 may have additional extension data, but the base Mint layout is identical to SPL Token.
func (s *tokenAccountService) GetTokenProgram(ctx context.Context, mint solana.PublicKey) (solana.PublicKey, uint8, error) {
	accountInfo, err := s.rpcClient.GetAccountInfo(ctx, mint)
	if err != nil {
		return solana.PublicKey{}, 0, fmt.Errorf("solana: failed to get mint account info: %w", err)
	}

	if accountInfo.Value == nil {
		return solana.PublicKey{}, 0, fmt.Errorf("solana: mint account not found: %s", mint)
	}

	owner := accountInfo.Value.Owner
	if owner != solana.TokenProgramID && owner != solana.Token2022ProgramID {
		return solana.PublicKey{}, 0, fmt.Errorf("solana: mint account is not owned by a token program: %s", owner)
	}

	data := accountInfo.Value.Data.GetBinary()
	var mintData token.Mint
	if err := mintData.UnmarshalWithDecoder(bin.NewBinDecoder(data)); err != nil {
		return solana.PublicKey{}, 0, fmt.Errorf("solana: failed to deserialize mint data: %w", err)
	}

	return owner, mintData.Decimals, nil
}

// FindAssociatedTokenAddress derives the ATA address for any token program (SPL or Token-2022).
// The tokenProgram parameter should be either solana.TokenProgramID or solana.Token2022ProgramID.
func FindAssociatedTokenAddress(wallet, mint, tokenProgram solana.PublicKey) (solana.PublicKey, uint8, error) {
	return solana.FindProgramAddress(
		[][]byte{
			wallet[:],
			tokenProgram[:],
			mint[:],
		},
		solana.SPLAssociatedTokenAccountProgramID,
	)
}

func (s *tokenAccountService) GetAssociatedTokenAddress(owner, mint, tokenProgram solana.PublicKey) (solana.PublicKey, error) {
	a, _, err := FindAssociatedTokenAddress(owner, mint, tokenProgram)
	if err != nil {
		return solana.PublicKey{}, fmt.Errorf("solana: failed to get associated token address: %w", err)
	}
	return a, nil
}

func (s *tokenAccountService) CheckAccountExists(ctx context.Context, account solana.PublicKey) (bool, error) {
	accountInfo, err := s.rpcClient.GetAccountInfo(ctx, account)
	if err != nil {
		if errors.Is(err, rpc.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("solana: failed to get account info: %w", err)
	}
	return accountInfo.Value != nil, nil
}

// BuildCreateATAInstruction creates an instruction to create an ATA for any token program.
// The tokenProgram should be either solana.TokenProgramID or solana.Token2022ProgramID.
func (s *tokenAccountService) BuildCreateATAInstruction(
	payer, owner, mint, tokenProgram solana.PublicKey,
) (solana.Instruction, error) {
	ataAddress, _, err := FindAssociatedTokenAddress(owner, mint, tokenProgram)
	if err != nil {
		return nil, fmt.Errorf("solana: failed to derive ATA address: %w", err)
	}

	return solana.NewInstruction(
		solana.SPLAssociatedTokenAccountProgramID,
		[]*solana.AccountMeta{
			{PublicKey: payer, IsSigner: true, IsWritable: true},
			{PublicKey: ataAddress, IsSigner: false, IsWritable: true},
			{PublicKey: owner, IsSigner: false, IsWritable: false},
			{PublicKey: mint, IsSigner: false, IsWritable: false},
			{PublicKey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
			{PublicKey: tokenProgram, IsSigner: false, IsWritable: false},
		},
		[]byte{0}, // instruction discriminator for "Create"
	), nil
}

func (s *tokenAccountService) BuildCreateATATransaction(
	ctx context.Context,
	payer, owner, mint, tokenProgram solana.PublicKey,
) (*solana.Transaction, error) {
	a, err := s.GetAssociatedTokenAddress(owner, mint, tokenProgram)
	if err != nil {
		return nil, fmt.Errorf("solana: failed to get associated token address: %w", err)
	}

	exists, err := s.CheckAccountExists(ctx, a)
	if err != nil {
		return nil, fmt.Errorf("solana: failed to check if ATA exists: %w", err)
	}

	if exists {
		return nil, fmt.Errorf("solana: associated token account already exists")
	}

	inst, err := s.BuildCreateATAInstruction(payer, owner, mint, tokenProgram)
	if err != nil {
		return nil, err
	}

	block, err := s.rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("solana: failed to get recent blockhash: %w", err)
	}

	tx, err := solana.NewTransaction(
		[]solana.Instruction{inst},
		block.Value.Blockhash,
		solana.TransactionPayer(payer),
	)
	if err != nil {
		return nil, fmt.Errorf("solana: failed to create transaction: %w", err)
	}

	return tx, nil
}

func (s *tokenAccountService) GetTokenBalance(ctx context.Context, tokenAccount solana.PublicKey) (uint64, error) {
	balance, err := s.rpcClient.GetTokenAccountBalance(ctx, tokenAccount, rpc.CommitmentFinalized)
	if err != nil {
		if errors.Is(err, rpc.ErrNotFound) {
			return 0, nil
		}

		errStr := err.Error()
		if strings.Contains(errStr, "could not find account") {
			return 0, nil
		}

		return 0, fmt.Errorf("solana: failed to get token balance: %w", err)
	}

	if balance.Value == nil || balance.Value.Amount == "" {
		return 0, nil
	}

	var amount uint64
	_, er := fmt.Sscanf(balance.Value.Amount, "%d", &amount)
	if er != nil {
		return 0, fmt.Errorf("solana: failed to parse amount: %w", er)
	}

	return amount, nil
}

func (s *tokenAccountService) BuildCloseTokenAccountTransaction(
	ctx context.Context,
	owner, tokenAccount, tokenProgram solana.PublicKey,
) (*solana.Transaction, error) {
	exists, err := s.CheckAccountExists(ctx, tokenAccount)
	if err != nil {
		return nil, fmt.Errorf("solana: failed to check if token account exists: %w", err)
	}

	if !exists {
		return nil, nil
	}

	block, err := s.rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("solana: failed to get recent blockhash: %w", err)
	}

	closeInst := solana.NewInstruction(
		tokenProgram,
		[]*solana.AccountMeta{
			{PublicKey: tokenAccount, IsWritable: true, IsSigner: false},
			{PublicKey: owner, IsWritable: true, IsSigner: false},
			{PublicKey: owner, IsWritable: false, IsSigner: true},
		},
		[]byte{9}, // CloseAccount instruction discriminator
	)

	tx, err := solana.NewTransaction(
		[]solana.Instruction{closeInst},
		block.Value.Blockhash,
		solana.TransactionPayer(owner),
	)
	if err != nil {
		return nil, fmt.Errorf("solana: failed to create transaction: %w", err)
	}

	return tx, nil
}
