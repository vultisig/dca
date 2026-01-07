# App-Recurring Stack - Run Cheatsheet

## Library Path (required)
```bash
export DYLD_LIBRARY_PATH=/Users/dev/dev/vultisig/go-wrappers/includes/darwin/:$DYLD_LIBRARY_PATH
```

## 1. Start Infrastructure
```bash
docker network create shared_network  # once

docker run -d --name app-recurring-postgres -p 5431:5432 \
  -e POSTGRES_USER=myuser -e POSTGRES_PASSWORD=mypassword -e POSTGRES_DB=dca \
  --network shared_network postgres:15

docker run -d --name app-recurring-redis -p 6378:6379 \
  --network shared_network redis:7 redis-server --requirepass password

docker run -d --name app-recurring-minio -p 9100:9000 -p 9190:9090 \
  -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  --network shared_network minio/minio server /data --console-address ":9090"
```

## 2. Create MinIO Bucket & Copy Vault
```bash
# Create bucket
docker exec app-recurring-minio mc alias set local http://localhost:9000 minioadmin minioadmin
docker exec app-recurring-minio mc mb local/vultisig-dca

# Copy vault file from verifier MinIO (required for signature verification)
docker exec verifier-minio-1 mc alias set local http://localhost:9000 minioadmin minioadmin
docker exec verifier-minio-1 mc cp local/vultisig-verifier/vultisig-dca-0000-*.vult /tmp/
docker cp verifier-minio-1:/tmp/vultisig-dca-0000-*.vult /tmp/
docker cp /tmp/vultisig-dca-0000-*.vult app-recurring-minio:/tmp/
docker exec app-recurring-minio mc cp /tmp/vultisig-dca-0000-*.vult local/vultisig-dca/
```

## 3. Run Services

### Server - SWAP Mode (port 8082)
```bash
MODE=swap \
BLOCKSTORAGE_ACCESSKEY=minioadmin BLOCKSTORAGE_BUCKET=vultisig-dca \
BLOCKSTORAGE_HOST=http://localhost:9100 BLOCKSTORAGE_REGION=us-east-1 BLOCKSTORAGE_SECRETKEY=minioadmin \
POSTGRES_DSN="postgres://myuser:mypassword@localhost:5431/dca?sslmode=disable" \
REDIS_URI="redis://:password@localhost:6378" \
SERVER_ENCRYPTIONSECRET=test123 SERVER_HOST=0.0.0.0 SERVER_PORT=8082 \
METRICS_ENABLED=true METRICS_PORT=8089 \
go run ./cmd/server/main.go
```

### Server - SEND Mode (port 8083)
```bash
MODE=send \
BLOCKSTORAGE_ACCESSKEY=minioadmin BLOCKSTORAGE_BUCKET=vultisig-dca \
BLOCKSTORAGE_HOST=http://localhost:9100 BLOCKSTORAGE_REGION=us-east-1 BLOCKSTORAGE_SECRETKEY=minioadmin \
POSTGRES_DSN="postgres://myuser:mypassword@localhost:5431/dca?sslmode=disable" \
REDIS_URI="redis://:password@localhost:6378" \
SERVER_ENCRYPTIONSECRET=test123 SERVER_HOST=0.0.0.0 SERVER_PORT=8083 \
METRICS_ENABLED=true METRICS_PORT=8093 \
go run ./cmd/server/main.go
```

### Scheduler
```bash
POSTGRES_DSN="postgres://myuser:mypassword@localhost:5431/dca?sslmode=disable" \
REDIS_URI="redis://:password@localhost:6378" \
HEALTHPORT=8181 METRICS_ENABLED=true METRICS_PORT=8090 \
go run ./cmd/scheduler/main.go
```

### Worker
```bash
BLOCKSTORAGE_ACCESSKEY=minioadmin BLOCKSTORAGE_BUCKET=vultisig-dca \
BLOCKSTORAGE_HOST=http://localhost:9100 BLOCKSTORAGE_REGION=us-east-1 BLOCKSTORAGE_SECRETKEY=minioadmin \
POSTGRES_DSN="postgres://myuser:mypassword@localhost:5431/dca?sslmode=disable" \
REDIS_URI="redis://:password@localhost:6378" \
RPC_ETHEREUM_URL=https://ethereum-rpc.publicnode.com \
RPC_ARBITRUM_URL=https://arbitrum-rpc.publicnode.com \
RPC_BASE_URL=https://base-rpc.publicnode.com \
RPC_BSC_URL=https://bsc-rpc.publicnode.com \
RPC_POLYGON_URL=https://polygon-bor-rpc.publicnode.com \
RPC_AVALANCHE_URL=https://avalanche-c-chain-rpc.publicnode.com \
RPC_OPTIMISM_URL=https://optimism-rpc.publicnode.com \
RPC_BLAST_URL=https://blast-rpc.publicnode.com \
RPC_SOLANA_URL=https://solana-rpc.publicnode.com \
RPC_XRP_URL=https://xrplcluster.com \
THORCHAIN_URL=https://thornode.ninerealms.com \
ONEINCH_BASEURL=https://api.vultisig.com/1inch \
SOLANA_JUPITERAPIURL=https://api.vultisig.com/jup \
BTC_BLOCKCHAIRURL=https://api.vultisig.com/blockchair \
VAULTSERVICE_RELAY_SERVER=https://api.vultisig.com/router \
VAULTSERVICE_LOCALPARTYPREFIX=vultisig-dca-0000 VAULTSERVICE_ENCRYPTIONSECRET=test123 VAULTSERVICE_DOSETUPMSG=true \
VERIFIER_URL=http://localhost:8080 VERIFIER_TOKEN=localhost-apikey-dca VERIFIER_PARTYPREFIX=verifier \
HEALTHPORT=8184 METRICS_ENABLED=true METRICS_PORT=8091 \
go run ./cmd/worker/main.go
```

### TX Indexer
```bash
BASE_DATABASE_DSN="postgres://myuser:mypassword@localhost:5431/dca?sslmode=disable" \
BASE_RPC_ETHEREUM_URL=https://ethereum-rpc.publicnode.com \
BASE_RPC_ARBITRUM_URL=https://arbitrum-rpc.publicnode.com \
BASE_RPC_BASE_URL=https://base-rpc.publicnode.com \
BASE_RPC_BSC_URL=https://bsc-rpc.publicnode.com \
BASE_RPC_POLYGON_URL=https://polygon-bor-rpc.publicnode.com \
BASE_RPC_AVALANCHE_URL=https://avalanche-c-chain-rpc.publicnode.com \
BASE_RPC_OPTIMISM_URL=https://optimism-rpc.publicnode.com \
BASE_RPC_BLAST_URL=https://blast-rpc.publicnode.com \
BASE_RPC_SOLANA_URL=https://solana-rpc.publicnode.com \
BASE_RPC_XRP_URL=https://xrplcluster.com \
BASE_RPC_BITCOIN_URL=bitcoin-rpc.publicnode.com \
BASE_INTERVAL=30s BASE_ITERATIONTIMEOUT=30s BASE_MARKLOSTAFTER=2h BASE_CONCURRENCY=5 \
HEALTHPORT=8183 METRICS_ENABLED=true METRICS_PORT=8092 \
go run ./cmd/tx_indexer/main.go
```

## Quick Reference

| Service | Port | Mode |
|---------|------|------|
| Server (DCA) | 8082 | `swap` |
| Server (Send) | 8083 | `send` |
| Scheduler | 8181 | - |
| Worker | 8184 | - |
| TX Indexer | 8183 | - |
| PostgreSQL | 5431 | `dca` db |
| Redis | 6378 | pass: `password` |
| MinIO | 9100 | |

**Requires:** Verifier stack running on `localhost:8080`

## Stop
```bash
docker stop app-recurring-postgres app-recurring-redis app-recurring-minio
docker rm app-recurring-postgres app-recurring-redis app-recurring-minio
pkill -f "go run ./cmd"
```
