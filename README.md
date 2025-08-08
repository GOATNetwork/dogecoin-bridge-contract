## Deployed Contracts

> Goat Testnet

| Contract       | Address                                    |
| -------------- | ------------------------------------------ |
| DogeToken      | 0x1F684c8F9b15350Bed21bb7EceE570D7CF629D23 |
| Dogechain      | 0x08459E0CE8136B8DD31088567a25D4ead80a1101 |
| DogecoinBridge | 0xE31f99D0F64f9E0A1b2855aA4f4D0888Ba14aC22 |

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

```shell
$ forge script script/DogecoinBridge.s.sol:DogecoinBridgeScript --rpc-url <your_rpc_url> --private-key <your_private_key> --broadcast --verify --verifier-url <your_verifier_url> --verifier-key <your_verifier_key>
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```
