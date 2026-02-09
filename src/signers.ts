// Copyright (c) 2025 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { isTaprootInput, tapTweakHash } from './compat';
import type { PsbtLike } from './psbt';
import type { ECPairInterface, BIP32Interface } from './types';

function range(n: number): number[] {
  return [...Array(n).keys()];
}

/**
 * Signs a specific input of a PSBT with an ECPair.
 *
 * Unlike bitcoinjs-lib's native `psbt.signInput()`, this function automatically detects
 * if the input is a Taproot input and internally tweaks the key if needed.
 *
 * This behavior matches how `signInputBIP32` works, where the BIP32 node is automatically
 * tweaked for Taproot inputs.
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
  const input = psbt.data.inputs[index];
  if (!input) throw new Error('Invalid index');
  if (isTaprootInput(input as Record<string, unknown>)) {
    // If script-path (tapLeafScript present) -> DO NOT TWEAK
    if (
      (input as Record<string, unknown>)['tapLeafScript'] &&
      Array.isArray((input as Record<string, unknown>)['tapLeafScript']) &&
      ((input as Record<string, unknown>)['tapLeafScript'] as unknown[]).length > 0
    )
      psbt.signInput(index, ecpair);
    else {
      const hash = tapTweakHash(
        Buffer.from(ecpair.publicKey.slice(1, 33)),
        undefined
      );
      const tweakedEcpair = ecpair.tweak(hash);
      psbt.signInput(index, tweakedEcpair);
    }
  } else psbt.signInput(index, ecpair);
}

/**
 * Signs all inputs of a PSBT with an ECPair.
 *
 * This function automatically handles Taproot inputs. For each input, it detects
 * if it's a Taproot input and internally tweaks the key if needed.
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
  const results: boolean[] = [];
  for (const index of range(psbt.data.inputs.length)) {
    try {
      signInputECPair({ psbt, index, ecpair });
      results.push(true);
    } catch (err) {
      void err;
      results.push(false);
    }
  }
  if (results.every(v => v === false)) {
    throw new Error('No inputs were signed');
  }
}

/**
 * Signs a specific input of a PSBT with a BIP32 node.
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
  psbt.signInputHD(index, node);
}

/**
 * Signs all inputs of a PSBT with a BIP32 master node.
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
  psbt.signAllInputsHD(masterNode);
}
