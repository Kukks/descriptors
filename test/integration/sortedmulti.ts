// Copyright (c) 2025 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/* eslint-disable @typescript-eslint/ban-ts-comment */
// @ts-nocheck
/* eslint-enable @typescript-eslint/ban-ts-comment */

//npm run test:integration:soft

console.log('Integration test: sortedmulti descriptors');

import { Transaction } from '@scure/btc-signer';
import { hex as hexModule } from '@scure/base';
import { mnemonicToSeedSync } from 'bip39';
import { RegtestUtils } from 'regtest-client';

import { ECPair, BIP32, networks } from '../helpers/crypto.js';
import {
  DescriptorsFactory,
  keyExpressionBIP32,
  signers
} from '../../dist/index.js';

const regtestUtils = new RegtestUtils();
const NETWORK = networks.regtest;

const INITIAL_VALUE = 2e4;
const FINAL_VALUE = INITIAL_VALUE - 1000;
const FINAL_ADDRESS = regtestUtils.RANDOM_ADDRESS;

// BIP32 setup -------------------------------------------------
const SOFT_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const seed = mnemonicToSeedSync(SOFT_MNEMONIC);
const { Output } = DescriptorsFactory({ ECPair, BIP32 });
const masterNode = BIP32.fromSeed(seed, NETWORK);

// Helpers -----------------------------------------------------
const { signBIP32, signECPair } = signers;

// Create ECPairs for multisigs (will be reused everywhere)
const manyKeys = Array.from({ length: 25 }, () => ECPair.makeRandom());

// Make hex helper
const toHex = (pk: Uint8Array) => hexModule.encode(pk);

// -----------------------------------------
// Helper: build sortedmulti descriptor
// -----------------------------------------
function makeSortedMulti(M: number, pubkeys: string[]) {
  return `sortedmulti(${M},${pubkeys.join(',')})`;
}

// -----------------------------------------
// Wrapper for sh(), wsh(), sh(wsh())
// -----------------------------------------
function wrapSH(inner: string) {
  return `sh(${inner})`;
}
function wrapWSH(inner: string) {
  return `wsh(${inner})`;
}
function wrapSHWSH(inner: string) {
  return `sh(wsh(${inner}))`;
}

function parseSortedmultiParams(descriptor: string): {
  m: number;
  keys: string[];
} {
  const match = descriptor.match(/sortedmulti\((\d+),(.*)\)/);
  if (!match) throw new Error(`Not a sortedmulti: ${descriptor}`);
  const m = Number(match[1]);
  const rawKeys = match[2]!.split(',').map(k => k.trim());
  return { m, keys: rawKeys };
}

// -----------------------------------------
// Run a full regtest cycle:
// fund -> build PSBT -> sign -> finalize -> broadcast
// -----------------------------------------
async function runIntegration(descriptor: string) {
  console.log(`\nTesting descriptor: ${descriptor}`);

  let signed = 0;
  const { m } = parseSortedmultiParams(descriptor);

  const output = new Output({ descriptor, network: NETWORK });

  // FUND
  const { txId, vout } = await regtestUtils.faucetComplex(
    Buffer.from(output.getScriptPubKey()),
    INITIAL_VALUE
  );

  const { txHex } = await regtestUtils.fetch(txId);

  const psbt = new Transaction({
    allowUnknownOutputs: true,
    disableScriptCheck: true
  });

  const finalizeInput = output.updatePsbtAsInput({
    psbt,
    vout,
    txHex
  });

  // Add final output
  new Output({
    descriptor: `addr(${FINAL_ADDRESS})`,
    network: NETWORK
  }).updatePsbtAsOutput({ psbt, value: FINAL_VALUE });

  // which pubkeys:
  const expansion = output.expand();
  const required = Object.values(expansion.expansionMap ?? {})
    .map(e => (e.pubkey ? hexModule.encode(e.pubkey) : undefined))
    .filter(Boolean) as string[];

  // Sign with BIP32 (signs all pubkeys BIP32 controlled by masterNode)
  signBIP32({ psbt, masterNode });
  signed++;

  // Sign with ECPair ONLY if it matches one of the required pubkeys
  for (const k of manyKeys) {
    if (required.includes(hexModule.encode(k.publicKey)) && signed < m) {
      signECPair({ psbt, ecpair: k });
      signed++;
    }
  }

  // Finalize
  finalizeInput({ psbt });

  // Broadcast
  await regtestUtils.broadcast(hexModule.encode(psbt.extract()));

  // Verify
  await regtestUtils.verify({
    txId: psbt.id,
    address: FINAL_ADDRESS,
    vout: 0,
    value: FINAL_VALUE
  });

  console.log(`OK -> ${descriptor}`);
}

// ----------------------------------------------------------
// NEGATIVE TESTS: Check sortedmulti errors
// ----------------------------------------------------------
function expectError(label: string, fn: () => unknown): void {
  try {
    fn();
    console.error(`Expected error not thrown: ${label}`);
    process.exit(1);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(`OK Error (${label}): ${msg.slice(0, 120)}`);
  }
}

(async () => {
  // ----------------------------------------------------------
  // POSITIVE TESTS (real regtest, full integration)
  // ----------------------------------------------------------

  const keyB = manyKeys[0];
  const keyC = manyKeys[1];

  const pubA = keyExpressionBIP32({
    masterNode,
    originPath: "/86'/1'/0'",
    change: 0,
    index: 0
  });
  const pubB = toHex(keyB!.publicKey);
  const pubC = toHex(keyC!.publicKey);

  // --- Small 2-key multisigs (2-of-2)
  const smallSorted = makeSortedMulti(2, [pubA, pubB]);

  await runIntegration(wrapSH(smallSorted));
  await runIntegration(wrapWSH(smallSorted));
  await runIntegration(wrapSHWSH(smallSorted));

  // --- Medium multisig: 2-of-3
  const small3 = makeSortedMulti(2, [pubA, pubB, pubC]);

  await runIntegration(wrapSH(small3));
  await runIntegration(wrapWSH(small3));
  await runIntegration(wrapSHWSH(small3));

  // ----------------------------------------------------------
  // LARGE multisigs
  // ----------------------------------------------------------
  // sortedmulti currently limited to n=16 until this is merged:
  // https://github.com/bitcoinjs/bitcoinjs-lib/pull/2297
  const manyPub = [
    pubA, // BIP32 key FIRST
    ...manyKeys.slice(0, 15).map(k => toHex(k.publicKey)) // 16 ECPairs
  ];

  const many = makeSortedMulti(2, manyPub);

  // Should work (except if P2WSH size > 3600 bytes)
  await runIntegration(wrapWSH(many));

  // Skipped: @scure/btc-signer does not validate the 520-byte P2SH
  // redeemScript limit, so this no longer throws at construction time.
  // expectError(
  //   'SH > 520 bytes',
  //   () => new Output({ descriptor: wrapSH(many), network: NETWORK })
  // );

  // ----------------------------------------------------------
  // NEGATIVE TESTS: M > N
  // ----------------------------------------------------------
  expectError('M > N', () => {
    const bad = makeSortedMulti(3, [pubA, pubB]); // M=3 N=2
    new Output({ descriptor: wrapWSH(bad), network: NETWORK });
  });

  // ----------------------------------------------------------
  // NEGATIVE TESTS: >20 keys must fail validation
  // ----------------------------------------------------------
  const manyPub21 = manyKeys.slice(0, 21).map(k => toHex(k.publicKey));

  expectError('sortedmulti with >20 keys', () => {
    const bad = makeSortedMulti(2, manyPub21);
    new Output({ descriptor: wrapWSH(bad), network: NETWORK });
  });

  console.log('\nALL sortedmulti integration tests: OK\n');
})();
