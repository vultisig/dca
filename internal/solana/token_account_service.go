package solana

import (
	"context"
	"errors"
	"fmt"

	"github.com/gagliardetto/solana-go"
	ata "github.com/gagliardetto/solana-go/programs/associated-token-account"
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

func (s *tokenAccountService) GetAssociatedTokenAddress(owner, mint solana.PublicKey) (solana.PublicKey, error) {
	a, _, err := solana.FindAssociatedTokenAddress(owner, mint)
	if err != nil {
		return solana.PublicKey{}, fmt.Errorf("failed to get associated token address: %w", err)
	}
	return a, nil
}

func (s *tokenAccountService) CheckAccountExists(ctx context.Context, account solana.PublicKey) (bool, error) {
	accountInfo, err := s.rpcClient.GetAccountInfo(ctx, account)
	if err != nil {
		if errors.Is(err, rpc.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("failed to get account info: %w", err)
	}
	return accountInfo.Value != nil, nil
}

func (s *tokenAccountService) BuildCreateATAInstruction(
	payer, owner, mint solana.PublicKey,
) solana.Instruction {
	createInstruction := ata.NewCreateInstruction(
		payer,
		owner,
		mint,
	).Build()

	return createInstruction
}

func (s *tokenAccountService) BuildCreateATATransaction(
	ctx context.Context,
	payer, owner, mint solana.PublicKey,
) (*solana.Transaction, error) {
	a, err := s.GetAssociatedTokenAddress(owner, mint)
	if err != nil {
		return nil, fmt.Errorf("failed to get associated token address: %w", err)
	}

	exists, err := s.CheckAccountExists(ctx, a)
	if err != nil {
		return nil, fmt.Errorf("failed to check if ATA exists: %w", err)
	}

	if exists {
		return nil, fmt.Errorf("associated token account already exists")
	}

	inst := s.BuildCreateATAInstruction(payer, owner, mint)

	block, err := s.rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent blockhash: %w", err)
	}

	tx, err := solana.NewTransaction(
		[]solana.Instruction{inst},
		block.Value.Blockhash,
		solana.TransactionPayer(payer),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}

	return tx, nil
}
