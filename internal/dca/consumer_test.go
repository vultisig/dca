package dca

import (
	"testing"

	ecommon "github.com/ethereum/go-ethereum/common"
)

func TestEvmPubToAddress(t *testing.T) {
	tests := []struct {
		name    string
		pub     string
		want    string
		wantErr bool
	}{
		{
			name:    "valid uncompressed public key with 0x04 prefix",
			pub:     "0x04e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606672ebc45e0b7ea2e816ecb70ca03137b1c9476eec63d4632e990020b7b6fba39",
			want:    "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1",
			wantErr: false,
		},
		{
			name:    "valid uncompressed public key without 0x prefix",
			pub:     "04e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606672ebc45e0b7ea2e816ecb70ca03137b1c9476eec63d4632e990020b7b6fba39",
			want:    "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1",
			wantErr: false,
		},
		{
			name:    "valid public key without 0x04 prefix",
			pub:     "e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606672ebc45e0b7ea2e816ecb70ca03137b1c9476eec63d4632e990020b7b6fba39",
			want:    "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1",
			wantErr: false,
		},
		{
			name:    "valid public key with 0x prefix but no 04",
			pub:     "0xe68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606672ebc45e0b7ea2e816ecb70ca03137b1c9476eec63d4632e990020b7b6fba39",
			want:    "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1",
			wantErr: false,
		},
		{
			name:    "another valid public key",
			pub:     "0x046f2da95c22af1d3da406fccf5f2dea1b685c4d1fccc263cd65d95517728dbf7e1c72a602c912e7ad6fef99e5a02d689470e12306863e2c65e5cc16f2e0e8e8b7",
			want:    "0xFFcf8FDEE72ac11b5c542428B35EEF5769C409f0",
			wantErr: false,
		},
		{
			name:    "third valid public key",
			pub:     "0x04d1f2cfb985e7d2e1c8f6a259e1a0ed7e5d01c5b7f8c56e9bb2628c3f3d90a96533a5f740c3e56969c8e5d085c248d5e08ad4b224629a9e89a943a3869db84f90",
			want:    "0x22d491Bde2303f2f43325b2108D26f1eAbA1e32b",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evmPubToAddress(tt.pub)
			if (err != nil) != tt.wantErr {
				t.Errorf("evmPubToAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				want := ecommon.HexToAddress(tt.want)
				if got != want {
					t.Errorf("evmPubToAddress() = %v, want %v", got.Hex(), want.Hex())
				}
			}
		})
	}
}
