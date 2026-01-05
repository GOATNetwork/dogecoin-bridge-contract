## Deployed Contracts

> Goat Testnet3

| Contract       | Address                                    | Status  |
| -------------- | ------------------------------------------ | -------  |
| DogeToken      | 0x9a0c41778b647a0f8a597766269aba9a3e2cc8e1 | ✅ Deployed (2026-01-05) |
| EntryPointUpgradeable | 0x3dedBd55E0120601553cEB6c92D9C2A8a1E06b66 | ✅ Deployed (2026-01-05) |
| Dogechain      | 0xba25DB001ED3b4e275aAa5CafE13549fa65587Fd | ✅ Deployed (2026-01-05) |
| DogecoinBridge | 0x104109EbeCA7dC4F4e7967F158404E67efeF55F9 | ✅ Deployed (2026-01-05) |

## Deployment Parameters

| Parameter | Value | Description |
| --------- | ------ | ----------- |
| **Owner** | 0x80BCcc69E2DCdf75E30132082Cb00B21f5EbF00b | Deployer address |
| **TSS_SIGNER** | 0x927C6216357888B6cbd46758dCcdbb9F25D0d639 | Updated to new address |
| **PROPOSER_1** | 0xE07dc2f6112E5B38237cb9620eA0075eF25e5E79 | First proposer |
| **PROPOSER_2** | 0x4E6588f5eb6D328ABB46df71C74D7031cC962C85 | Second proposer |
| **PROPOSER_3** | 0xe0a189c72078AB9A4B0ebfcd3eEf46153392a152 | Third proposer |
| **feeRate** | 0 | 0% (free) |
| **DogecoinBridgePK** | 0xFc456386689dfe8e94dfcfae8a0b953eb91d140b | Bridge-in public key hash |
| **opReturnMagicPrefix** | 0x47514556 | GQEV prefix |
| **dogecoinNetwork** | TESTNET | Dogecoin testnet |

## Previous Addresses

| Contract       | Old Address                                     |
| -------------- | ---------------------------------------------- |
| DogeToken      | - |
| EntryPointUpgradeable | 0x5E043a024fAd7AE6f1BF94A17a2a785572380270 |
| Dogechain      | 0x0B024eaB3a49311B56fBEbe1b93Ca23Abd7fB9ea |
| DogecoinBridge | 0xB1c2c0425976db612fa141b6BC4C02B5e46d3EeF |

## Verification

```bash
# Verify TSS_SIGNER
cast call 0x3dedBd55E0120601553cEB6c92D9C2A8a1E06b66 "tssSigner()" --rpc-url https://rpc.testnet3.goat.network

# Verify feeRate
cast call 0x104109EbeCA7dC4F4e7967F158404E67efeF55F9 "feeRate()" --rpc-url https://rpc.testnet3.goat.network
```

## Deployment Details

- **Deploy Date**: 2026-01-05
- **Network**: Goat Testnet3 (Chain ID: 48816)
- **RPC**: https://rpc.testnet3.goat.network
- **Explorer**: https://explorer.testnet3.goat.network

## Configuration Files Updated

- `/Users/drej/Projects/ops/ops-goat-testnet3/testnet/relayer/ansible/playbooks/files/relayer/dogecoin/config.yaml`
