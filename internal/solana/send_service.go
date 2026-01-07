package solana

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
)

type sendService struct {
	rpcClient *rpc.Client
}

func newSendService(rpcClient *rpc.Client) *sendService {
	return &sendService{
		rpcClient: rpcClient,
	}
}

func (s *sendService) BuildNativeTransfer(
	ctx context.Context,
	from solana.PublicKey,
	to solana.PublicKey,
	amount uint64,
) ([]byte, error) {
	accountInfo, err := s.rpcClient.GetAccountInfo(ctx, to)
	if err != nil && err.Error() != "not found" {
		return nil, fmt.Errorf("failed to check destination account: %w", err)
	}

	accountExists := accountInfo != nil && accountInfo.Value != nil

	if !accountExists {
		rentExempt, err := s.rpcClient.GetMinimumBalanceForRentExemption(ctx, 0, rpc.CommitmentFinalized)
		if err != nil {
			return nil, fmt.Errorf("failed to get rent exemption: %w", err)
		}

		if amount < rentExempt {
			return nil, fmt.Errorf(
				"transfer amount %d lamports is below rent-exempt minimum %d lamports for new account",
				amount,
				rentExempt,
			)
		}
	}

	block, err := s.rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent blockhash: %w", err)
	}

	transferInst := system.NewTransferInstruction(
		amount,
		from,
		to,
	).Build()

	tx, err := solana.NewTransaction(
		[]solana.Instruction{transferInst},
		block.Value.Blockhash,
		solana.TransactionPayer(from),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}

	txBytes, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transaction: %w", err)
	}

	return txBytes, nil
}

func (s *sendService) BuildSPLTransfer(
	ctx context.Context,
	mint solana.PublicKey,
	fromOwner solana.PublicKey,
	toOwner solana.PublicKey,
	amount uint64,
	tokenProgram solana.PublicKey,
) ([]byte, error) {
	sourceATA, _, err := FindAssociatedTokenAddress(fromOwner, mint, tokenProgram)
	if err != nil {
		return nil, fmt.Errorf("failed to find source ATA: %w", err)
	}

	destATA, _, err := FindAssociatedTokenAddress(toOwner, mint, tokenProgram)
	if err != nil {
		return nil, fmt.Errorf("failed to find destination ATA: %w", err)
	}

	block, err := s.rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent blockhash: %w", err)
	}

	// Build transfer instruction data: discriminator (1 byte) + amount (8 bytes little-endian)
	data := make([]byte, 9)
	data[0] = 3 // Transfer instruction discriminator
	binary.LittleEndian.PutUint64(data[1:], amount)

	transferInst := solana.NewInstruction(
		tokenProgram,
		[]*solana.AccountMeta{
			{PublicKey: sourceATA, IsSigner: false, IsWritable: true},
			{PublicKey: destATA, IsSigner: false, IsWritable: true},
			{PublicKey: fromOwner, IsSigner: true, IsWritable: false},
		},
		data,
	)

	tx, err := solana.NewTransaction(
		[]solana.Instruction{transferInst},
		block.Value.Blockhash,
		solana.TransactionPayer(fromOwner),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}

	txBytes, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transaction: %w", err)
	}

	return txBytes, nil
}
