// Copyright (c) 2025 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import * as btc from '@scure/btc-signer';
import { bip32Path } from '@scure/btc-signer';
import { RawTx, RawOldTx } from '@scure/btc-signer/script.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hex } from '@scure/base';
import { equalBytes } from '@scure/btc-signer/utils.js';
import type { KeyInfo } from './types.js';
import { decompileScript, readUInt32BE } from './scriptUtils.js';

// PsbtLike is now an alias for @scure/btc-signer's Transaction class.
// The Transaction class handles PSBT natively: addInput/Output, sign, finalize, extract.
type PsbtLike = InstanceType<typeof btc.Transaction>;

/**
 * Computes final scripts for miniscript-based inputs.
 *
 * @param scriptSatisfaction - The script satisfaction (input script data)
 * @param lockingScript - The "meaningful" locking script (witnessScript or redeemScript)
 * @param isSegwit - Whether this is a segwit input
 * @param isP2SH - Whether this is a P2SH input
 * @param network - The network
 * @returns Object with finalScriptSig and finalScriptWitness (as Uint8Array[])
 */
export function computeFinalScripts(
  scriptSatisfaction: Uint8Array,
  lockingScript: Uint8Array,
  isSegwit: boolean,
  isP2SH: boolean,
  redeemScript?: Uint8Array
): {
  finalScriptSig: Uint8Array | undefined;
  finalScriptWitness: Uint8Array[] | undefined;
} {
  let finalScriptWitness: Uint8Array[] | undefined;
  let finalScriptSig: Uint8Array | undefined;

  // Helper: decompile scriptSatisfaction into witness items
  function satisfactionToWitness(): Uint8Array[] {
    const chunks = decompileScript(scriptSatisfaction);
    if (!chunks)
      throw new Error('Could not decompile script satisfaction');
    return chunks.map(chunk =>
      typeof chunk === 'number'
        ? new Uint8Array(0) // OP_0 or opcodes become empty push
        : chunk
    );
  }

  //p2wsh: witness = [satisfaction chunks..., witnessScript]
  if (isSegwit && !isP2SH) {
    const witness = satisfactionToWitness();
    witness.push(lockingScript);
    finalScriptWitness = witness;
  }
  //p2sh-p2wsh: witness = [satisfaction chunks..., witnessScript], scriptSig = push of redeemScript
  else if (isSegwit && isP2SH) {
    const witness = satisfactionToWitness();
    witness.push(lockingScript);
    finalScriptWitness = witness;
    // finalScriptSig is a serialized script that pushes the redeemScript
    const rs = redeemScript ?? lockingScript;
    finalScriptSig = btc.Script.encode([rs]);
  }
  //p2sh: scriptSig = satisfaction + push of redeemScript
  else {
    // Build scriptSig: scriptSatisfaction bytes + push of lockingScript (redeemScript)
    const chunks = decompileScript(scriptSatisfaction);
    if (!chunks)
      throw new Error('Could not decompile script satisfaction');
    const scriptItems: (number | Uint8Array)[] = chunks.map(chunk =>
      typeof chunk === 'number'
        ? chunk
        : chunk
    );
    scriptItems.push(lockingScript);
    finalScriptSig = btc.Script.encode(scriptItems);
  }

  return { finalScriptSig, finalScriptWitness };
}

/**
 * Important: Read comments on descriptor.updatePsbt regarding not passing txHex
 */
export function updatePsbt({
  psbt,
  vout,
  txHex,
  txId,
  value,
  sequence,
  locktime,
  keysInfo,
  scriptPubKey,
  isSegwit,
  tapInternalKey,
  witnessScript,
  redeemScript,
  rbf
}: {
  psbt: PsbtLike;
  vout: number;
  txHex?: string;
  txId?: string;
  value?: number | bigint;
  sequence: number | undefined;
  locktime: number | undefined;
  keysInfo: KeyInfo[];
  scriptPubKey: Uint8Array;
  isSegwit: boolean;
  /** for taproot **/
  tapInternalKey?: Uint8Array | undefined;
  witnessScript: Uint8Array | undefined;
  redeemScript: Uint8Array | undefined;
  rbf: boolean;
}): number {
  //Some data-sanity checks:
  if (sequence !== undefined && rbf && sequence > 0xfffffffd)
    throw new Error(`Error: incompatible sequence and rbf settings`);
  if (!isSegwit && txHex === undefined)
    throw new Error(`Error: txHex is mandatory for Non-Segwit inputs`);
  if (
    isSegwit &&
    txHex === undefined &&
    (txId === undefined || value === undefined)
  )
    throw new Error(`Error: pass txHex or txId+value for Segwit inputs`);
  if (txHex !== undefined) {
    const rawTxBytes = hex.decode(txHex);
    // Use RawTx.decode instead of Transaction.fromRaw to avoid script
    // validation that rejects bare P2PK and other non-wrapped output types.
    const parsed = RawTx.decode(rawTxBytes);
    const out = parsed.outputs[vout];
    if (!out) throw new Error(`Error: tx ${txHex} does not have vout ${vout}`);
    const outputScript = out.script;
    if (!outputScript)
      throw new Error(
        `Error: could not extract outputScript for txHex ${txHex} and vout ${vout}`
      );
    if (!equalBytes(outputScript, scriptPubKey))
      throw new Error(
        `Error: txHex ${txHex} for vout ${vout} does not correspond to scriptPubKey ${hex.encode(scriptPubKey)}`
      );
    // Compute txid: double-SHA256 of non-witness serialization, reversed
    const nonWitnessSerialization = RawOldTx.encode(parsed);
    const txidHash = sha256(sha256(nonWitnessSerialization));
    const computedTxId = hex.encode(txidHash.slice().reverse());
    if (txId !== undefined) {
      if (computedTxId !== txId)
        throw new Error(
          `Error: txId for ${txHex} and vout ${vout} does not correspond to ${txId}`
        );
    } else {
      txId = computedTxId;
    }
    if (value !== undefined) {
      if (BigInt(out.amount) !== BigInt(value))
        throw new Error(
          `Error: value for ${txHex} and vout ${vout} does not correspond to ${value}`
        );
    } else {
      value = BigInt(out.amount);
    }
  }
  if (txId === undefined || !value)
    throw new Error(
      `Error: txHex+vout required. Alternatively, but ONLY for Segwit inputs, txId+value can also be passed.`
    );

  if (locktime) {
    const currentLocktime = psbt.lockTime;
    if (currentLocktime && currentLocktime !== locktime && currentLocktime !== 0)
      throw new Error(
        `Error: transaction locktime was already set with a different value: ${locktime} != ${currentLocktime}`
      );
    // nLockTime only works if at least one of the transaction inputs has an
    // nSequence value that is below 0xffffffff. Let's make sure that at least
    // this input's sequence < 0xffffffff
    if (sequence === undefined) {
      sequence = rbf ? 0xfffffffd : 0xfffffffe;
    } else if (sequence > 0xfffffffe) {
      throw new Error(
        `Error: incompatible sequence: ${sequence} and locktime: ${locktime}`
      );
    }
    if (sequence === undefined && rbf) sequence = 0xfffffffd;
    // Set locktime via scure's internal global field
    (psbt as any).global.fallbackLocktime = locktime;
  } else {
    if (sequence === undefined) {
      if (rbf) sequence = 0xfffffffd;
      else sequence = 0xffffffff;
    }
  }

  // Build input in @scure/btc-signer format
  const input: Record<string, unknown> = {
    txid: hex.decode(txId),
    index: vout
  };
  if (txHex !== undefined) {
    input['nonWitnessUtxo'] = hex.decode(txHex);
  }

  if (tapInternalKey) {
    //Taproot
    const tapBip32Derivation: [Uint8Array, { hashes: Uint8Array[]; der: { fingerprint: number; path: number[] } }][] = keysInfo
      .filter(
        (keyInfo: KeyInfo) =>
          keyInfo.pubkey && keyInfo.masterFingerprint && keyInfo.path
      )
      .map((keyInfo: KeyInfo) => {
        const pubkey = keyInfo.pubkey;
        if (!pubkey)
          throw new Error(`key ${keyInfo.keyExpression} missing pubkey`);
        return [
          pubkey,
          {
            hashes: [] as Uint8Array[], // Empty for tr(KEY) taproot key spend
            der: {
              fingerprint: readUInt32BE(keyInfo.masterFingerprint!),
              path: bip32Path(keyInfo.path!)
            }
          }
        ] as [Uint8Array, { hashes: Uint8Array[]; der: { fingerprint: number; path: number[] } }];
      });

    if (tapBip32Derivation.length)
      input['tapBip32Derivation'] = tapBip32Derivation;
    input['tapInternalKey'] = tapInternalKey;

    //TODO: currently only single-key taproot supported.
    if (tapBip32Derivation.length > 1)
      throw new Error('Only single key taproot inputs are currently supported');
  } else {
    const bip32Derivation: [Uint8Array, { fingerprint: number; path: number[] }][] = keysInfo
      .filter(
        (keyInfo: KeyInfo) =>
          keyInfo.pubkey && keyInfo.masterFingerprint && keyInfo.path
      )
      .map((keyInfo: KeyInfo) => {
        const pubkey = keyInfo.pubkey;
        if (!pubkey)
          throw new Error(`key ${keyInfo.keyExpression} missing pubkey`);
        return [
          pubkey,
          {
            fingerprint: readUInt32BE(keyInfo.masterFingerprint!),
            path: bip32Path(keyInfo.path!)
          }
        ] as [Uint8Array, { fingerprint: number; path: number[] }];
      });
    if (bip32Derivation.length) input['bip32Derivation'] = bip32Derivation;
  }
  if (isSegwit && txHex !== undefined) {
    //There's no need to put both witnessUtxo and nonWitnessUtxo
    input['witnessUtxo'] = { script: scriptPubKey, amount: BigInt(value!) };
  }
  if (sequence !== undefined) input['sequence'] = sequence;

  if (witnessScript) input['witnessScript'] = witnessScript;
  if (redeemScript) input['redeemScript'] = redeemScript;

  psbt.addInput(input as any);
  return psbt.inputsLength - 1;
}

export type { PsbtLike };
