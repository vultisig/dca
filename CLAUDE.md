# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a DCA (Dollar Cost Averaging) plugin for the Vultisig ecosystem that enables automated, recurring cryptocurrency swaps across multiple EVM chains using Uniswap V2. The plugin operates as part of a larger policy-based transaction verification system, supporting 8 EVM networks with official Uniswap V2 deployments.

## Architecture

### Core Components

The system consists of four main services that can be run independently:

1. **Server (`cmd/server/`)** - REST API server that handles policy management and provides the main plugin interface
2. **Scheduler (`cmd/scheduler/`)** - Background worker that schedules DCA transactions based on configured intervals
3. **Worker (`cmd/worker/`)** - Task consumer that executes DCA swaps and handles key signing operations
4. **TX Indexer (`cmd/tx_indexer/`)** - Blockchain transaction indexer for monitoring and verification

### Key Modules

- **`internal/dca/`** - Core DCA logic including policy specs, scheduling, and transaction consumption
- **`internal/evm/`** - EVM blockchain abstraction layer with network management and approval services
- **`internal/btc/`** - Bitcoin network integration with PSBT support
- **`internal/solana/`** - Solana blockchain integration with token account management
- **`internal/uniswap/`** - Uniswap V2 integration for EVM-based DEX swapping
- **`internal/thorchain/`** - THORChain integration for cross-chain swaps (BTC, EVM)
- **`internal/jupiter/`** - Jupiter DEX aggregator integration for Solana swaps
- **`internal/graceful/`** - Graceful shutdown handling

### Plugin System Integration

The DCA plugin integrates with the Vultisig verifier system through:
- **Policy specifications** (`spec.go`) - Defines supported operations, parameters, and constraints
- **Recipe configuration** - JSON schema validation for DCA parameters
- **Rule generation** - Creates policy rules for Uniswap V2 operations (swapExactTokensForTokens, swapExactETHForTokens, etc.)

## Dependencies

### Core Dependencies
- **Ethereum integration**: `github.com/ethereum/go-ethereum` for blockchain interactions
- **Task queuing**: `github.com/hibiken/asynq` with Redis for background job processing
- **Database**: PostgreSQL with `github.com/jackc/pgx/v5` for persistence
- **Web framework**: `github.com/labstack/echo/v4` for REST API
- **Configuration**: Environment-based config using `github.com/kelseyhightower/envconfig`

### Vultisig Dependencies
- `github.com/vultisig/recipes` - Recipe system and blockchain abstractions
- `github.com/vultisig/verifier` - Policy verification and plugin framework
- `github.com/vultisig/go-wrappers` - Native cryptographic library wrappers (DKLS)

### Blockchain Dependencies
- `github.com/gagliardetto/solana-go` - Solana blockchain SDK
- `github.com/btcsuite/btcd` - Bitcoin protocol implementation

## Configuration

All services use environment-based configuration. Key configuration areas:

- **Database**: PostgreSQL connection settings
- **Redis**: Task queue and caching configuration  
- **Blockchain RPCs**: Multi-chain EVM node endpoints (publicnode.com)
- **Uniswap**: Official Uniswap V2 router contract addresses for all supported chains
- **Vault**: Block storage and key management settings
- **DataDog**: Metrics and monitoring integration

## DCA Workflow

1. **Policy Creation** - User configures DCA parameters (frequency, assets, amounts)
2. **Recipe Validation** - System validates configuration against JSON schema
3. **Rule Generation** - Creates Uniswap V2 operation rules with parameter constraints
4. **Scheduling** - Scheduler queues transactions based on frequency settings, respecting endDate constraints
5. **Execution** - Worker processes queued tasks, handling approvals and swaps
6. **Key Signing** - Integrates with Vultisig's distributed key signing system

### Supported Operations

The plugin generates rules for these Uniswap V2 operations:
- `swapExactTokensForTokens` - ERC20 to ERC20 swaps
- `swapExactETHForTokens` - ETH to ERC20 swaps  
- `swapExactTokensForETH` - ERC20 to ETH swaps
- ERC20 `approve` operations for token allowances

### Frequency Options

- `minutely` (60s), `hourly` (3600s), `daily` (86400s)
- `weekly` (604800s), `bi-weekly` (1209600s), `monthly` (2592000s)

## Build and Development

### Building Services

```bash
# Build specific service (replace SERVICE with server/scheduler/worker/tx_indexer)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o main cmd/${SERVICE}/main.go

# Build all services
for service in server scheduler worker tx_indexer; do
    go build -o bin/$service cmd/$service/main.go
done
```

### Docker Build

The Dockerfile supports building any service:

```bash
docker build --build-arg SERVICE=server -t dca-server .
docker build --build-arg SERVICE=worker -t dca-worker .
```

### Testing

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./internal/dca/
go test ./internal/uniswap/
```

### Development Setup

1. **PostgreSQL** - Required for policy and scheduler storage
2. **Redis** - Required for task queuing
3. **Ethereum RPC** - Mainnet or testnet endpoint
4. **Environment variables** - Configure all services appropriately

## Important Implementation Details

### Transaction Building

- Uniswap V2 integration calculates optimal swap amounts and handles slippage (configured via `slippageBips`)
- Automatic approval checking and transaction building for ERC20 tokens
- Deadline management for time-sensitive DEX operations

### Key Management

- Public key to Ethereum address conversion using Keccak256 hashing
- Integration with Vultisig's distributed key signing (DKLS) system
- Support for both local and remote signing parties

### Policy Constraints

- Fixed parameter constraints for swap amounts and token addresses
- Dynamic deadline and slippage parameters
- Rate limiting based on DCA frequency settings (maxTxsPerWindow: 2)

### Error Handling

- Comprehensive validation at multiple layers (JSON schema, business logic)
- Graceful degradation and retry mechanisms through asynq
- Detailed logging with structured formats

## Chain Support

Currently supports **8 EVM chains** with official Uniswap V2 deployments:

- **Ethereum** (`0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D`)
- **Arbitrum** (`0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24`)
- **Avalanche** (`0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24`) 
- **BNB Chain** (`0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24`)
- **Base** (`0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24`)
- **Blast** (`0xBB66Eb1c5e875933D44DAe661dbD80e5D9B03035`)
- **Optimism** (`0x4A7b5Da61326A6379179b40d00F57E5bbDC962c2`)
- **Polygon** (`0xedf6066a2b290C185783862C7F4776A2C8077AD1`)

The system uses the Vultisig recipes framework for blockchain abstractions and dynamically generates policy rules for all supported chains.

## Multi-Chain Architecture

### Dynamic Chain Support

The DCA plugin has been architected for seamless multi-chain expansion:

- **Dynamic Policy Generation**: The `spec.go` file automatically generates resource patterns and policy rules for all EVM chains
- **Chain-Agnostic Resource Paths**: Resource paths are dynamically constructed using chain names (e.g., `ethereum.uniswapV2_router.swapExactTokensForTokens`, `arbitrum.uniswapV2_router.swapExactTokensForTokens`)  
- **Unified Configuration**: Single configuration structure supports all chains with consistent environment variable patterns
- **Network Initialization**: Worker service automatically initializes EVM networks for all configured chains with appropriate RPC endpoints and router addresses

### Configuration Patterns

All chain-specific configurations follow consistent patterns:

```bash
# RPC Endpoints
RPC_{CHAIN}_URL="https://{chain}-rpc.publicnode.com"

# Uniswap V2 Routers (official addresses)
UNISWAP_ROUTERV2_{CHAIN}="0x{official_router_address}"

# TX Indexer RPCs
BASE_RPC_{CHAIN}_URL="https://{chain}-rpc.publicnode.com"
```

This design allows for easy addition of new EVM chains by simply adding their configuration without code changes.

## Monitoring and Observability

- DataDog integration for metrics and monitoring
- Structured logging with configurable levels
- Transaction indexing for audit and verification purposes
- Health check endpoints available on `/healthz` for all services
- Network-specific logging for multi-chain operations

## Recent Improvements

### Multi-Chain Expansion (Latest)

- **Expanded from Ethereum-only to 8 EVM chains** with official Uniswap V2 support
- **Updated all router addresses** to use official Uniswap V2 deployment addresses
- **Removed unsupported chains** (CronosChain, Zksync) that lack official Uniswap V2 deployments
- **Dynamic spec generation** for automatic policy rule creation across all chains
- **Unified configuration patterns** for consistent multi-chain management
- **Enhanced scheduler with endDate support** - automatically stops scheduling when policies expire

### Infrastructure Updates

- **Updated RPC endpoints** to use publicnode.com for reliable blockchain access
- **Enhanced Kubernetes manifests** with multi-chain ConfigMaps and environment variables
- **Improved GoLand run configurations** for local development across all chains
- **TX Indexer integration** expanded to support all EVM chains

### Code Quality & Architecture

- **Type-safe chain handling** using the recipes framework
- **Comprehensive error handling** with chain-specific validation
- **Consistent logging patterns** with chain identification
- **Maintainable configuration** through structured environment variable patterns
- **Zero breaking changes** while expanding functionality

## Development Best Practices

When working with this codebase:

1. **Chain Support**: Always consider multi-chain implications when making changes
2. **Configuration**: Follow the established `{SERVICE}_{CHAIN}_{CONFIG}` environment variable pattern
3. **Resource Paths**: Use lowercase chain names for resource path construction
4. **Router Addresses**: Only use official Uniswap V2 router addresses from [Uniswap docs](https://docs.uniswap.org/contracts/v2/reference/smart-contracts/v2-deployments)
5. **Testing**: Ensure all changes work across supported EVM chains
6. **Error Handling**: Include chain identification in error messages and logs