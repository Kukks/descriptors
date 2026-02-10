# @kukks/bitcoin-descriptors

> **Fork of [`@bitcoinerlab/descriptors`](https://github.com/bitcoinerlab/descriptors)** by [Jose-Luis Landabaso](https://github.com/landabaso).

This library parses and creates Bitcoin Miniscript Descriptors and generates Partially Signed Bitcoin Transactions (PSBTs). It provides PSBT finalizers and signers for single-signature and BIP32 wallets.

## Differences from upstream

This fork migrates the entire library from `bitcoinjs-lib` to the [`@scure/btc-signer`](https://github.com/nicolo-ribaudo/scure-btc-signer) and [`@noble`](https://github.com/nicolo-ribaudo/noble-curves) ecosystem. Key differences:

- **`Buffer` replaced with `Uint8Array`** across the entire public API. All methods that previously returned or accepted `Buffer` now use `Uint8Array`. This is a **breaking change**.
- **Dependencies replaced**: `bitcoinjs-lib`, `ecpair`, `bip32`, `tiny-secp256k1` are no longer used. The library now depends on `@scure/btc-signer`, `@scure/bip32`, `@noble/curves`, `@noble/hashes`, and `@scure/base`.
- **PSBT class**: Uses `Transaction` from `@scure/btc-signer` instead of `Psbt` from `bitcoinjs-lib`.
- **Ledger support removed**: The `ledger` module and all Ledger-related functions (`signLedger`, `keyExpressionLedger`, `pkhLedger`, `shWpkhLedger`, `wpkhLedger`, etc.) have been removed.
- **`lodash.memoize` removed**: Replaced with an inline memoize helper.
- **Package renamed** from `@bitcoinerlab/descriptors` to `@kukks/bitcoin-descriptors`.

## Installation

```bash
npm install @kukks/bitcoin-descriptors
npm install @bitcoinerlab/miniscript
```

## Features

- Parses and creates [Bitcoin Descriptors](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md) (including those based on the [Miniscript language](https://bitcoinerlab.com/modules/miniscript)).
- Generates Partially Signed Bitcoin Transactions (PSBTs).
- Provides PSBT finalizers and signers for single-signature and BIP32 wallets.

## Concepts

This library has two main capabilities related to Bitcoin descriptors. Firstly, it can generate `addresses` and `scriptPubKeys` from descriptors. These `addresses` and `scriptPubKeys` can be used to receive funds from other parties. Secondly, the library is able to sign transactions and spend unspent outputs described by those same descriptors. In order to do this, the descriptors must first be set into a PSBT.

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

The `Output` class is dynamically created by providing `ECPair` and `BIP32` factory APIs:

```javascript
import * as descriptors from '@kukks/bitcoin-descriptors';
const { Output } = descriptors.DescriptorsFactory({ ECPair, BIP32 });
```

Here, `ECPair` and `BIP32` are implementations of the `ECPairAPI` and `BIP32API` interfaces. These interfaces now use `Uint8Array` instead of `Buffer` for all binary data (public keys, private keys, signatures, etc.).

Once set up, you can obtain an instance for an output:

```javascript
const wpkhOutput = new Output({
  descriptor:
    'wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)'
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

```javascript
import { Transaction } from '@scure/btc-signer';
const psbt = new Transaction({ allowUnknownOutputs: true, disableScriptCheck: true });
const inputFinalizer = output.updatePsbtAsInput({ psbt, txHex, vout });
```

Here, `psbt` refers to an instance of the [`@scure/btc-signer` Transaction class](https://github.com/nicolo-ribaudo/scure-btc-signer). The parameter `txHex` denotes a hex string that serializes the previous transaction containing this output. Meanwhile, `vout` is an integer that marks the position of the output within that transaction.

The method returns the `inputFinalizer()` function. This finalizer function completes a PSBT input by adding the unlocking script (`scriptWitness` or `scriptSig`) that satisfies the previous output's spending conditions. Complete all necessary signing operations before calling `inputFinalizer()`.

To add an output:

```javascript
const recipientOutput =
 new Output({ descriptor: `addr(bc1qgw6xanldsz959z45y4dszehx4xkuzf7nfhya8x)` });
recipientOutput.updatePsbtAsOutput({ psbt, value: 10000 });
```

#### Parsing Descriptors with `expand()`

The `expand()` function parses Bitcoin descriptors into their component parts:

```javascript
const output = new Output({ descriptor: "your-descriptor-here" });
const result = output.expand();
```

Or through the factory:

```javascript
const { expand } = descriptors.DescriptorsFactory({ ECPair, BIP32 });
const result = expand({
  descriptor: "sh(wsh(andor(pk(0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2),older(8640),pk([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*))))"
});
```

### Signers and Finalizers

This library includes two signers: ECPair (single-signature) and BIP32.

```javascript
import { signers } from '@kukks/bitcoin-descriptors';

// For BIP32
signers.signBIP32({ psbt, masterNode });

// For ECPair
signers.signECPair({ psbt, ecpair });
```

#### Finalizing the PSBT

1. For each unspent output, call `updatePsbtAsInput`:

   ```javascript
   const inputFinalizer = output.updatePsbtAsInput({ psbt, txHex, vout });
   ```

2. After signing, finalize each input:

   ```javascript
   inputFinalizer({ psbt });
   ```

### Key Expressions and Script Expressions

Helper functions for generating descriptor strings:

```javascript
import { scriptExpressions, keyExpressionBIP32 } from '@kukks/bitcoin-descriptors';
```

The `scriptExpressions` module includes functions like `pkhBIP32()`, `shWpkhBIP32()`, and `wpkhBIP32()` for generating descriptors for commonly used scripts.

The `keyExpressionBIP32` function generates BIP32 key expression strings:

```javascript
keyExpressionBIP32({
  masterNode,     // BIP32Interface
  originPath,     // e.g. "/44'/0'/0'"
  change,         // 0 (receive) or 1 (change)
  index,          // number or '*'
  isPublic        // whether to use xpub or xprv
});
```

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
