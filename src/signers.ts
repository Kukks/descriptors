// Copyright (c) 2025 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { PsbtLike } from './psbt.js';
import type { ECPairInterface, BIP32Interface } from './types.js';

/**
 * Adapts a BIP32Interface node to the HDKey interface expected by @scure/btc-signer.
 * scure's Transaction.sign/signIdx auto-handle Taproot tweaking when given an HDKey.
 */
function toScureHDKey(node: BIP32Interface): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  fingerprint: number;
  derive(path: string): ReturnType<typeof toScureHDKey>;
  deriveChild(index: number): ReturnType<typeof toScureHDKey>;
  sign(hash: Uint8Array): Uint8Array;
} {
  if (!node.privateKey)
    throw new Error('Cannot create HDKey signer from neutered node');
  return {
    publicKey: new Uint8Array(node.publicKey),
    privateKey: new Uint8Array(node.privateKey),
    fingerprint: node.fingerprint.readUInt32BE(0),
    derive(path: string) {
      return toScureHDKey(node.derivePath(path));
    },
    deriveChild(index: number) {
      return toScureHDKey(node.derive(index));
    },
    sign(hash: Uint8Array): Uint8Array {
      return new Uint8Array(node.sign(Buffer.from(hash)));
    }
  };
}

/**
 * Derives the private key from a BIP32 node using tapBip32Derivation info
 * and signs the Taproot input directly with the raw private key.
 * This is needed because @scure/btc-signer's signIdx HDKey path only checks
 * bip32Derivation, not tapBip32Derivation.
 */
function signTapBip32(
  psbt: PsbtLike,
  index: number,
  masterNode: BIP32Interface
): boolean {
  const input = psbt.getInput(index);
  const tapBip32 = input.tapBip32Derivation as
    | [Uint8Array, { hashes: Uint8Array[]; der: { fingerprint: number; path: number[] } }][]
    | undefined;
  if (!tapBip32 || !tapBip32.length) return false;
  const fp = masterNode.fingerprint.readUInt32BE(0);
  let signed = false;
  for (const [, { der }] of tapBip32) {
    if (der.fingerprint !== fp) continue;
    let node: BIP32Interface = masterNode;
    for (const childIdx of der.path) {
      node = node.derive(childIdx);
    }
    if (!node.privateKey)
      throw new Error('Cannot sign: derived node has no private key');
    psbt.signIdx(new Uint8Array(node.privateKey), index);
    signed = true;
  }
  return signed;
}

/**
 * Signs a specific input of a PSBT with an ECPair.
 *
 * Uses @scure/btc-signer's signIdx which automatically handles
 * Taproot key tweaking internally.
 *
 * @param {Object} params - The parameters object
 * @param {PsbtLike} params.psbt - The PSBT to sign
 * @param {number} params.index - The input index to sign
 * @param {ECPairInterface} params.ecpair - The ECPair to sign with
 */
export function signInputECPair({
  psbt,
  index,
  ecpair
}: {
  psbt: PsbtLike;
  index: number;
  ecpair: ECPairInterface;
}): void {
  if (!ecpair.privateKey) throw new Error('Missing private key');
  psbt.signIdx(new Uint8Array(ecpair.privateKey), index);
}

/**
 * Signs all inputs of a PSBT with an ECPair.
 *
 * Uses @scure/btc-signer's sign which automatically handles
 * Taproot key tweaking internally.
 *
 * @param {Object} params - The parameters object
 * @param {PsbtLike} params.psbt - The PSBT to sign
 * @param {ECPairInterface} params.ecpair - The ECPair to sign with
 */
export function signECPair({
  psbt,
  ecpair
}: {
  psbt: PsbtLike;
  ecpair: ECPairInterface;
}): void {
  if (!ecpair.privateKey) throw new Error('Missing private key');
  const signed = psbt.sign(new Uint8Array(ecpair.privateKey));
  if (signed === 0) {
    throw new Error('No inputs were signed');
  }
}

/**
 * Signs a specific input of a PSBT with a BIP32 node.
 *
 * Handles Taproot inputs via tapBip32Derivation, and non-Taproot via
 * @scure/btc-signer's signIdx with an HDKey adapter.
 *
 * @param {Object} params - The parameters object
 * @param {PsbtLike} params.psbt - The PSBT to sign
 * @param {number} params.index - The input index to sign
 * @param {BIP32Interface} params.node - The BIP32 node to sign with
 */
export function signInputBIP32({
  psbt,
  index,
  node
}: {
  psbt: PsbtLike;
  index: number;
  node: BIP32Interface;
}): void {
  if (!signTapBip32(psbt, index, node)) {
    psbt.signIdx(toScureHDKey(node), index);
  }
}

/**
 * Signs all inputs of a PSBT with a BIP32 master node.
 *
 * First signs any Taproot inputs via tapBip32Derivation, then uses
 * @scure/btc-signer's sign for remaining non-Taproot inputs.
 *
 * @param {Object} params - The parameters object
 * @param {PsbtLike} params.psbt - The PSBT to sign
 * @param {BIP32Interface} params.masterNode - The BIP32 master node to sign with
 */
export function signBIP32({
  psbt,
  masterNode
}: {
  psbt: PsbtLike;
  masterNode: BIP32Interface;
}): void {
  let tapSigned = 0;
  for (let i = 0; i < psbt.inputsLength; i++) {
    if (signTapBip32(psbt, i, masterNode)) tapSigned++;
  }
  let nonTapSigned = 0;
  try {
    nonTapSigned = psbt.sign(toScureHDKey(masterNode));
  } catch (e) {
    // sign() throws 'No inputs signed' when no bip32Derivation matches
  }
  if (tapSigned + nonTapSigned === 0) {
    throw new Error('No inputs were signed');
  }
}
