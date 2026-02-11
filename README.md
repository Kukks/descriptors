# @kukks/bitcoin-descriptors

> **Fork of [`@bitcoinerlab/descriptors`](https://github.com/bitcoinerlab/descriptors)** by [Jose-Luis Landabaso](https://github.com/landabaso).

This library parses and creates Bitcoin Miniscript Descriptors and generates Partially Signed Bitcoin Transactions (PSBTs). It provides PSBT finalizers and signers for single-signature and BIP32 wallets.

## Differences from upstream

This fork migrates the entire library from `bitcoinjs-lib` to the [`@scure/btc-signer`](https://github.com/nicolo-ribaudo/scure-btc-signer) and [`@noble`](https://github.com/paulmillr/noble-curves) ecosystem. Key differences:

- **`Buffer` replaced with `Uint8Array`** across the entire public API. All methods that previously returned or accepted `Buffer` now use `Uint8Array`. This is a **breaking change**.
- **Dependencies replaced**: `bitcoinjs-lib`, `ecpair`, `bip32`, `tiny-secp256k1` are no longer used. The library now depends on [`@scure/btc-signer`](https://github.com/nicolo-ribaudo/scure-btc-signer), [`@scure/bip32`](https://github.com/nicolo-ribaudo/scure-bip32), [`@noble/curves`](https://github.com/paulmillr/noble-curves), [`@noble/hashes`](https://github.com/paulmillr/noble-hashes), and [`@scure/base`](https://github.com/nicolo-ribaudo/scure-base).
- **Built-in adapters**: Ships `nobleECPair` and `scureBIP32` adapters — no more boilerplate. `DescriptorsFactory()` works with zero arguments.
- **PSBT class**: Uses `Transaction` from `@scure/btc-signer` instead of `Psbt` from `bitcoinjs-lib`.
- **Ledger support removed**: The `ledger` module and all Ledger-related functions have been removed.
- **`lodash.memoize` removed**: Replaced with an inline memoize helper.
- **Package renamed** from `@bitcoinerlab/descriptors` to `@kukks/bitcoin-descriptors`.

## Installation

```bash
npm install @kukks/bitcoin-descriptors
npm install @bitcoinerlab/miniscript
```

## Quick Start

```typescript
import { DescriptorsFactory } from '@kukks/bitcoin-descriptors';

// Zero-config — uses built-in @noble/curves + @scure/bip32 adapters
const { Output, expand } = DescriptorsFactory();

const output = new Output({
  descriptor: 'wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)'
});

console.log(output.getAddress());
```

Or use the pre-built default factory:

```typescript
import { defaultFactory } from '@kukks/bitcoin-descriptors';

const { Output } = defaultFactory;
```

### Bring your own adapters

If you need custom `ECPairAPI` or `BIP32API` implementations, you can still pass them explicitly:

```typescript
import { DescriptorsFactory } from '@kukks/bitcoin-descriptors';
import type { ECPairAPI, BIP32API } from '@kukks/bitcoin-descriptors';

const { Output } = DescriptorsFactory({ ECPair: myECPair, BIP32: myBIP32 });
```

The built-in adapters are also available as standalone exports:

```typescript
import { nobleECPair, scureBIP32 } from '@kukks/bitcoin-descriptors';
```

## Features

- Parses and creates [Bitcoin Descriptors](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md) (including those based on the [Miniscript language](https://bitcoinerlab.com/modules/miniscript)).
- Generates Partially Signed Bitcoin Transactions (PSBTs).
- Provides PSBT finalizers and signers for single-signature and BIP32 wallets.
- Ships built-in adapters for `@noble/curves` and `@scure/bip32` — zero boilerplate needed.

<details>
  <summary>Concepts</summary>

### Descriptors

In Bitcoin, a transaction consists of a set of inputs that are spent into a different set of outputs. Each input spends an output in a previous transaction. A Bitcoin descriptor is a string of text that describes the rules and conditions required to spend an output in a transaction.

For example, `wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)` is a descriptor that describes a pay-to-witness-public-key-hash (P2WPKH) type of output with the specified public key. If you know the corresponding private key for the transaction for which this descriptor is an output, you can spend it.

Descriptors can express much more complex conditions, such as multi-party cooperation, time-locked outputs, and more. These conditions can be expressed using the Bitcoin Miniscript language, which is a way of writing Bitcoin Scripts in a structured and more easily understandable way.

### Partially Signed Bitcoin Transactions (PSBTs)

A PSBT (Partially Signed Bitcoin Transaction) is a format for sharing Bitcoin transactions between different parties.

PSBTs come in handy when working with descriptors, especially when using scripts, because they allow multiple parties to collaborate in the signing process.

</details>

## Usage

The library can be split into three main parts:

- The `Output` class is the central component for managing descriptors. It facilitates the creation of outputs to receive funds and enables the signing and finalization of PSBTs for spending UTXOs.
- PSBT signers and finalizers, which are used to manage the signing and finalization of PSBTs.
- `keyExpressions` and `scriptExpressions`, which provide functions to create key and standard descriptor expressions (strings) from structured data.

### Output class

The `Output` class is created via `DescriptorsFactory`:

```typescript
import { DescriptorsFactory } from '@kukks/bitcoin-descriptors';

const { Output } = DescriptorsFactory();

const wpkhOutput = new Output({
  descriptor: 'wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)'
});
```

For miniscript-based descriptors, the `signersPubKeys` parameter in the constructor becomes particularly important. It specifies the spending path of a previous output with multiple spending paths.

The `Output` class offers various helpful methods, including `getAddress()`, `getScriptPubKey()` (returns `Uint8Array`), `expand()`, `updatePsbtAsInput()` and `updatePsbtAsOutput()`.

The library supports a wide range of descriptor types, including:
- Pay-to-Public-Key-Hash (P2PKH): `pkh(KEY)`
- Pay-to-Witness-Public-Key-Hash (P2WPKH): `wpkh(KEY)`
- Pay-to-Script-Hash (P2SH): `sh(SCRIPT)`
- Pay-to-Witness-Script-Hash (P2WSH): `wsh(SCRIPT)`
- Pay-to-Taproot (P2TR) with single key: `tr(KEY)`
- Address-based descriptors: `addr(ADDRESS)`, including Taproot addresses

#### Working with PSBTs

This library uses `Transaction` from `@scure/btc-signer` as the PSBT class:

```typescript
import { Transaction } from '@scure/btc-signer';

const psbt = new Transaction({ allowUnknownOutputs: true, disableScriptCheck: true });
const inputFinalizer = output.updatePsbtAsInput({ psbt, txHex, vout });
```

Here, `psbt` refers to an instance of the [`@scure/btc-signer` Transaction class](https://github.com/nicolo-ribaudo/scure-btc-signer). The parameter `txHex` denotes a hex string that serializes the previous transaction containing this output. Meanwhile, `vout` is an integer that marks the position of the output within that transaction.

The method returns the `inputFinalizer()` function. This finalizer function completes a PSBT input by adding the unlocking script (`scriptWitness` or `scriptSig`) that satisfies the previous output's spending conditions. Complete all necessary signing operations before calling `inputFinalizer()`.

To add an output:

```typescript
const recipientOutput = new Output({
  descriptor: 'addr(bc1qgw6xanldsz959z45y4dszehx4xkuzf7nfhya8x)'
});
recipientOutput.updatePsbtAsOutput({ psbt, value: 10000 });
```

#### Parsing Descriptors with `expand()`

The `expand()` function parses Bitcoin descriptors into their component parts:

```typescript
const output = new Output({ descriptor: "your-descriptor-here" });
const result = output.expand();
```

Or through the factory:

```typescript
const { expand } = DescriptorsFactory();
const result = expand({
  descriptor: "sh(wsh(andor(pk(0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2),older(8640),pk([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*))))"
});
```

### Signers and Finalizers

This library includes two signers: ECPair (single-signature) and BIP32.

```typescript
import { signers } from '@kukks/bitcoin-descriptors';

// For BIP32
signers.signBIP32({ psbt, masterNode });

// For ECPair
signers.signECPair({ psbt, ecpair });
```

#### Finalizing the PSBT

1. For each unspent output, call `updatePsbtAsInput`:

   ```typescript
   const inputFinalizer = output.updatePsbtAsInput({ psbt, txHex, vout });
   ```

2. After signing, finalize each input:

   ```typescript
   inputFinalizer({ psbt });
   ```

### Key Expressions and Script Expressions

Helper functions for generating descriptor strings:

```typescript
import { scriptExpressions, keyExpressionBIP32 } from '@kukks/bitcoin-descriptors';
```

The `scriptExpressions` module includes functions like `pkhBIP32()`, `shWpkhBIP32()`, and `wpkhBIP32()` for generating descriptors for commonly used scripts.

The `keyExpressionBIP32` function generates BIP32 key expression strings:

```typescript
keyExpressionBIP32({
  masterNode,     // BIP32Interface
  originPath,     // e.g. "/44'/0'/0'"
  change,         // 0 (receive) or 1 (change)
  index,          // number or '*'
  isPublic        // whether to use xpub or xprv
});
```

## API Reference

### Exports

| Export | Type | Description |
|--------|------|-------------|
| `DescriptorsFactory` | function | Creates `Output`, `expand`, `parseKeyExpression` — params optional (defaults to built-in adapters) |
| `defaultFactory` | object | Pre-built factory using built-in adapters |
| `nobleECPair` | `ECPairAPI` | Built-in ECPair adapter using `@noble/curves` secp256k1 |
| `scureBIP32` | `BIP32API` | Built-in BIP32 adapter using `@scure/bip32` |
| `signers` | namespace | `signECPair`, `signBIP32` and related signing functions |
| `scriptExpressions` | namespace | `pkhBIP32`, `shWpkhBIP32`, `wpkhBIP32`, etc. |
| `keyExpressionBIP32` | function | Generate BIP32 key expression strings |
| `networks` | object | `bitcoin`, `testnet`, `regtest` network definitions |
| `checksum` | function | Compute/validate descriptor checksums |

### Types

| Type | Description |
|------|-------------|
| `ECPairAPI` | Factory interface for creating key pairs |
| `ECPairInterface` | Key pair instance with `sign`, `verify`, `publicKey`, etc. |
| `BIP32API` | Factory interface for creating HD keys (`fromSeed`, `fromBase58`, etc.) |
| `BIP32Interface` | HD key instance with `derivePath`, `derive`, `sign`, etc. |
| `OutputInstance` | Instance returned by `new Output(...)` |
| `Network` | Network configuration (`bitcoin`, `testnet`, `regtest`) |
| `PsbtLike` | PSBT interface (compatible with `@scure/btc-signer` Transaction) |
| `KeyInfo` | Parsed key expression data |
| `Expansion` | Parsed descriptor expansion data |

## Building from source

```bash
git clone https://github.com/Kukks/descriptors.git
cd descriptors/
npm install
npm run build
```

## Testing

Before running tests, start a Bitcoin regtest node using the preconfigured Docker image:

```bash
docker pull bitcoinerlab/tester
docker run -d -p 8080:8080 -p 60401:60401 -p 3002:3002 bitcoinerlab/tester
```

Then run:

```bash
npm run test
```

## License

This project is licensed under the MIT License.

## Credits

Originally developed by [Jose-Luis Landabaso](https://github.com/landabaso) at [bitcoinerlab](https://github.com/bitcoinerlab). This fork is maintained by [Kukks](https://github.com/Kukks).
