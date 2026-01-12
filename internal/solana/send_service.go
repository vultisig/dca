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
		return nil, fmt.Errorf("solana: failed to check destination account: %w", err)
	}

	accountExists := accountInfo != nil && accountInfo.Value != nil

	if !accountExists {
		rentExempt, err := s.rpcClient.GetMinimumBalanceForRentExemption(ctx, 0, rpc.CommitmentFinalized)
		if err != nil {
			return nil, fmt.Errorf("solana: failed to get rent exemption: %w", err)
		}

		if amount < rentExempt {
			return nil, fmt.Errorf(
				"solana: transfer amount %d lamports is below rent-exempt minimum %d lamports for new account",
				amount,
				rentExempt,
			)
		}
	}

	block, err := s.rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("solana: failed to get recent blockhash: %w", err)
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
		return nil, fmt.Errorf("solana: failed to create transaction: %w", err)
	}

	txBytes, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("solana: failed to marshal transaction: %w", err)
	}

	return txBytes, nil
}

// BuildTokenTransfer builds a token transfer transaction using transfer_checked instruction.
// transfer_checked is required for Token-2022 tokens and works for all SPL tokens.
func (s *sendService) BuildTokenTransfer(
	ctx context.Context,
	mint solana.PublicKey,
	fromOwner solana.PublicKey,
	toOwner solana.PublicKey,
	amount uint64,
	decimals uint8,
	tokenProgram solana.PublicKey,
) ([]byte, error) {
	sourceATA, _, err := findAssociatedTokenAddress(fromOwner, mint, tokenProgram)
	if err != nil {
		return nil, fmt.Errorf("solana: failed to find source ATA: %w", err)
	}

	destATA, _, err := findAssociatedTokenAddress(toOwner, mint, tokenProgram)
	if err != nil {
		return nil, fmt.Errorf("solana: failed to find destination ATA: %w", err)
	}

	block, err := s.rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("solana: failed to get recent blockhash: %w", err)
	}

	// Build transfer_checked instruction data: discriminator (1 byte) + amount (8 bytes) + decimals (1 byte)
	data := make([]byte, 10)
	data[0] = 12 // TransferChecked instruction discriminator
	binary.LittleEndian.PutUint64(data[1:9], amount)
	data[9] = decimals

	transferInst := solana.NewInstruction(
		tokenProgram,
		[]*solana.AccountMeta{
			{PublicKey: sourceATA, IsSigner: false, IsWritable: true},
			{PublicKey: mint, IsSigner: false, IsWritable: false},
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
		return nil, fmt.Errorf("solana: failed to create transaction: %w", err)
	}

	txBytes, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("solana: failed to marshal transaction: %w", err)
	}

	return txBytes, nil
}
