// Copyright (c) 2025 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

// BIP86: Taproot BIP32 Derivation Path and Extended Key Version
// https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki

import { DescriptorsFactory, scriptExpressions } from '../dist/index.js';
import { hex as hexModule } from '@scure/base';
import { mnemonicToSeedSync } from 'bip39';
import { ECPair, BIP32 } from './helpers/crypto.js';
const { trBIP32 } = scriptExpressions;
const { Output } = DescriptorsFactory({ ECPair, BIP32 });
const network = {
  messagePrefix: '\x18Bitcoin Signed Message:\n',
  bech32: 'bc',
  bip32: { public: 0x0488b21e, private: 0x0488ade4 },
  pubKeyHash: 0x00,
  scriptHash: 0x05,
  wif: 0x80
};
const masterNode = BIP32.fromSeed(
  mnemonicToSeedSync(
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
  ),
  network
);

describe('BIP86 Taproot Derivation Path Tests', () => {
  // Test vector from BIP86 specification
  // https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#test-vectors

  test("First receiving address m/86'/0'/0'/0/0", () => {
    const descriptor = trBIP32({
      masterNode,
      network,
      account: 0,
      change: 0,
      index: 0
    });

    const output = new Output({ descriptor, network });
    const address = output.getAddress();
    const scriptPubKey = hexModule.encode(output.getScriptPubKey());
    const payment = output.getPayment() as Record<string, unknown>;
    const internalKey = payment['tapInternalKey']
      ? hexModule.encode(payment['tapInternalKey'] as Uint8Array)
      : undefined;
    const pubKey = payment['tweakedPubkey']
      ? hexModule.encode(payment['tweakedPubkey'] as Uint8Array)
      : undefined;

    expect(address).toBe(
      'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr'
    );

    expect(scriptPubKey).toBe(
      '5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c'
    );

    expect(internalKey).toBe(
      'cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115'
    );

    expect(pubKey).toBe(
      'a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c'
    );
  });

  test('Basic Taproot descriptor functionality', () => {
    const descriptor = trBIP32({
      masterNode,
      network,
      account: 0,
      change: 0,
      index: 0
    });

    const output = new Output({ descriptor, network });

    expect(output.getAddress()).toBeTruthy();
    expect(output.getAddress().startsWith('bc1p')).toBe(true);
    expect(output.isTaproot()).toBe(true);
  });
});
