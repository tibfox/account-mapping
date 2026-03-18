# Account Mapping Contracts

TinyGo WASM smart contracts that bridge account-based blockchains to the VSC/Magi network.

Unlike the [UTXO mapping contracts](https://github.com/vsc-eco/utxo-mapping) which verify deposits via SPV merkle proofs, account-based chains use oracle-submitted deposits — an authorized oracle calls `map` with deposit details.

## Supported Chains

| Chain | Status | Tests |
|-------|--------|-------|
| ETH   | Partial — token ops work, Map/Unmap not implemented | 43 |

## What Works

- `transfer` / `transferFrom` — move mapped tokens between VSC addresses
- `approve` / `increaseAllowance` / `decreaseAllowance` — ERC-20 style allowances
- Address validation via `sdk.VerifyAddress()`

## What's Missing

- `map` — stub, no oracle deposit submission flow
- `unmap` — not implemented (ETH withdrawals need a different approach than UTXO tx construction)
- No mapping bot chain adapter
- No DEX integration tested
- No block header or receipt proof validation

## Future Chains

This repo is where Solana, Avalanche, Polygon, Arbitrum, and other account-based chains would go.

## Building

```bash
cd eth-mapping-contract
USE_DOCKER=1 make dev
```

## Testing

```bash
cd eth-mapping-contract
make test
```
