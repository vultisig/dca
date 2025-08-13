# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a DCA (Dollar Cost Averaging) plugin for the Vultisig ecosystem that enables automated, recurring cryptocurrency swaps on Ethereum using Uniswap V2. The plugin operates as part of a larger policy-based transaction verification system.

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
- **`internal/uniswap/`** - Uniswap V2 integration for DEX swapping functionality
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

## Configuration

All services use environment-based configuration. Key configuration areas:

- **Database**: PostgreSQL connection settings
- **Redis**: Task queue and caching configuration  
- **Blockchain RPCs**: Ethereum node endpoints
- **Uniswap**: Router contract addresses per chain
- **Vault**: Block storage and key management settings
- **DataDog**: Metrics and monitoring integration

## DCA Workflow

1. **Policy Creation** - User configures DCA parameters (frequency, assets, amounts)
2. **Recipe Validation** - System validates configuration against JSON schema
3. **Rule Generation** - Creates Uniswap V2 operation rules with parameter constraints
4. **Scheduling** - Scheduler queues transactions based on frequency settings
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

Currently supports **Ethereum mainnet only**, with architecture designed for multi-chain expansion. The system uses the Vultisig recipes framework for blockchain abstractions.

## Monitoring and Observability

- DataDog integration for metrics and monitoring
- Structured logging with configurable levels
- Transaction indexing for audit and verification purposes