# Vultisig DCA Plugin

A Dollar Cost Averaging (DCA) plugin for the Vultisig ecosystem that enables automated, recurring cryptocurrency swaps across multiple chains.

**Note**: Uniswap V2 support has been removed. The plugin is being migrated to use 1inch as the DEX aggregator for EVM networks.

## Overview

The DCA plugin operates as part of Vultisig's policy-based transaction verification system, allowing users to set up automated recurring swaps with configurable frequency, amounts, and assets. The system leverages distributed key signing (DKLS) for secure transaction execution.

## Supported Networks

### EVM Chains
- **Ethereum**
- **Arbitrum**
- **Avalanche**
- **BNB Chain**
- **Base**
- **Blast**
- **Optimism**
- **Polygon**

### Other Chains
- **Bitcoin**
- **Solana**
- **XRP**

## Architecture

### Core Services

The system consists of four independently deployable services:

#### 1. **Server** (`cmd/server/`)
REST API server that handles policy management and provides the main plugin interface.

**Key Features:**
- Policy creation and validation
- Recipe specification management
- Multi-chain swap configuration

#### 2. **Scheduler** (`cmd/scheduler/`)
Background worker that schedules DCA transactions based on configured intervals.

**Supported Frequencies:**
- `minutely` (60s)
- `hourly` (3600s) 
- `daily` (86400s)
- `weekly` (604800s)
- `bi-weekly` (1209600s)
- `monthly` (2592000s)

#### 3. **Worker** (`cmd/worker/`)
Task consumer that executes DCA swaps and handles distributed key signing operations.

**Key Features:**
- Multi-chain network initialization
- Swap execution (migrating to 1inch for EVM chains)
- ERC20 approval management
- Distributed key signing integration

#### 4. **TX Indexer** (`cmd/tx_indexer/`)
Blockchain transaction indexer for monitoring and verification.

### Key Modules

- **`internal/dca/`** - Core DCA logic, policy specs, and transaction consumption
- **`internal/evm/`** - EVM blockchain abstraction with multi-network support
- **`internal/graceful/`** - Graceful shutdown handling

## DCA Workflow

1. **Policy Creation** - User configures DCA parameters through the API
2. **Recipe Validation** - System validates configuration against JSON schema
3. **Rule Generation** - Creates swap operation rules with parameter constraints
4. **Scheduling** - Scheduler queues transactions based on frequency settings, respecting endDate constraints
5. **Execution** - Worker processes tasks, handling approvals and swaps
6. **Key Signing** - Integrates with Vultisig's distributed key signing system


## Configuration

### Environment Variables

All services use environment-based configuration:

#### Common Configuration
```bash
# Database
POSTGRES_DSN="postgres://user:pass@host:port/dbname?sslmode=disable"

# Redis (Task Queue)
REDIS_HOST="localhost"
REDIS_PORT="6379"
REDIS_PASSWORD="password"

# Block Storage
BLOCKSTORAGE_HOST="localhost:9100"
BLOCKSTORAGE_REGION="us-east-1"
BLOCKSTORAGE_ACCESSKEY="access-key"
BLOCKSTORAGE_SECRETKEY="secret-key"
BLOCKSTORAGE_BUCKET="bucket-name"

# DataDog
DATADOG_HOST="localhost"
DATADOG_PORT="8125"
```

#### Worker-Specific Configuration
```bash
# Vault Service
VAULTSERVICE_RELAY_SERVER="https://api.vultisig.com/router"
VAULTSERVICE_LOCALPARTYPREFIX="vultisig-dca-0000"
VAULTSERVICE_ENCRYPTIONSECRET="encryption-secret"

# Verifier
VERIFIER_URL="http://localhost:8080"
VERIFIER_TOKEN="api-token"
VERIFIER_PARTYPREFIX="verifier"

# RPC URLs (per chain)
RPC_ETHEREUM_URL="https://ethereum-rpc.publicnode.com"
RPC_ARBITRUM_URL="https://arbitrum-rpc.publicnode.com"
RPC_AVALANCHE_URL="https://avalanche-c-chain-rpc.publicnode.com"
RPC_DASH_URL="https://dash-rpc.publicnode.com"
RPC_MAYACHAIN_URL="https://mayanode.mayachain.info"
# ... (other chains)
```

## Building and Deployment

### Local Development

#### Build Services
```bash
# Build specific service
go build -o bin/server cmd/server/main.go
go build -o bin/worker cmd/worker/main.go
go build -o bin/scheduler cmd/scheduler/main.go
go build -o bin/tx_indexer cmd/tx_indexer/main.go

# Build all services
for service in server worker scheduler tx_indexer; do
    go build -o bin/$service cmd/$service/main.go
done
```

#### Run Tests
```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./internal/dca/
```

### Docker Deployment

```bash
# Build Docker images
docker build --build-arg SERVICE=server -t dca-server .
docker build --build-arg SERVICE=worker -t dca-worker .
docker build --build-arg SERVICE=scheduler -t dca-scheduler .
docker build --build-arg SERVICE=tx_indexer -t dca-tx-indexer .
```

### Kubernetes Deployment

Deploy using the provided manifests in the `deploy/` directory:

```bash
# Apply all manifests
kubectl apply -f deploy/

# Or apply in order
kubectl apply -f deploy/00_ns.yaml
kubectl apply -f deploy/01_*.yaml
kubectl apply -f deploy/02_*.yaml
kubectl apply -f deploy/03_*.yaml
```

## API Usage

### Create DCA Policy

```json
POST /api/policy

{
  "fromChain": "Ethereum",
  "fromAsset": "0xA0b86a33E6441439C01695E5481c061F0e6bB4F5",
  "fromAmount": "100000000000000000000",
  "toChain": "Ethereum", 
  "toAsset": "0x0000000000000000000000000000000000000000",
  "toAddress": "0x742d35Cc6634C0532925a3b8D1B9b12a6B43B9a8",
  "frequency": "daily",
  "endDate": "2024-12-31T23:59:59Z"
}
```

### Supported Parameters

- **fromChain/toChain**: Must be same chain (cross-chain not supported)
- **fromAsset/toAsset**: Contract addresses (`0x0000...` for native tokens)
- **fromAmount**: Amount in wei (string)
- **frequency**: `minutely`, `hourly`, `daily`, `weekly`, `bi-weekly`, `monthly`
- **toAddress**: Recipient address
- **endDate**: ISO 8601 timestamp (optional) - scheduler stops scheduling new runs after this date

## Dependencies

### Core Dependencies
- **Ethereum**: `github.com/ethereum/go-ethereum` - Blockchain interactions
- **Task Queue**: `github.com/hibiken/asynq` with Redis - Background jobs
- **Database**: PostgreSQL with `github.com/jackc/pgx/v5` - Data persistence
- **Web Framework**: `github.com/labstack/echo/v4` - REST API
- **Configuration**: `github.com/kelseyhightower/envconfig` - Environment config

### Vultisig Dependencies
- `github.com/vultisig/recipes` - Recipe system and blockchain abstractions
- `github.com/vultisig/verifier` - Policy verification and plugin framework
- `github.com/vultisig/go-wrappers` - Native cryptographic library wrappers (DKLS)

## Development Setup

### Prerequisites
1. **PostgreSQL** - For policy and scheduler storage
2. **Redis** - For task queuing
3. **Ethereum RPC** - Mainnet or testnet endpoint
4. **Go 1.21+** - For building the services

### Environment Setup
1. Copy environment variables from GoLand run configurations (`.run/*.xml`)
2. Update database and Redis connection strings
3. Configure RPC endpoints for desired chains
4. Set up Vultisig vault and verifier integration

## Monitoring

- **DataDog Integration** - Metrics and monitoring
- **Structured Logging** - Configurable log levels
- **Health Checks** - Available on `/healthz` endpoint
- **Transaction Indexing** - Audit trail and verification

## Security Considerations

- Distributed key signing (DKLS) for secure transaction execution
- Policy-based access control through Vultisig verifier
- Rate limiting: Maximum 2 transactions per frequency window
- Slippage protection and deadline management for DEX operations

## Contributing

1. Follow existing code patterns and conventions
2. Ensure all tests pass: `go test ./...`
3. Update documentation for new features
4. Use structured logging for observability
