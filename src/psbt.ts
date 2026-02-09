// Copyright (c) 2025 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import * as btc from '@scure/btc-signer';
import { RawTx, RawOldTx } from '@scure/btc-signer/script';
import { sha256 } from '@noble/hashes/sha256';
import { hex } from '@scure/base';
import type { KeyInfo, PartialSig } from './types';
import {
  Network,
  toPayment,
  toBtcSignerNetwork,
  varintEncodingLength,
  varintEncode
} from './compat';

// Local type definitions replacing bip174 types
interface Bip32Derivation {
  masterFingerprint: Buffer;
  pubkey: Buffer;
  path: string;
}
interface TapBip32Derivation extends Bip32Derivation {
  leafHashes: Buffer[];
}
interface PsbtInput {
  witnessUtxo?: { script: Buffer; value: number };
  nonWitnessUtxo?: Buffer;
  partialSig?: PartialSig[];
  witnessScript?: Buffer;
  redeemScript?: Buffer;
  bip32Derivation?: Bip32Derivation[];
  tapBip32Derivation?: TapBip32Derivation[];
  tapInternalKey?: Buffer;
  [key: string]: unknown;
}
interface PsbtInputExtended extends PsbtInput {
  hash: Buffer;
  index: number;
  sequence?: number;
}

/**
 * This function must do two things:
 * 1. Check if the `input` can be finalized. If it can not be finalized, throw.
 *   ie. `Can not finalize input #${inputIndex}`
 * 2. Create the finalScriptSig and finalScriptWitness Buffers.
 */
type FinalScriptsFunc = (
  inputIndex: number, // Which input is it?
  input: PsbtInput, // The PSBT input contents
  script: Buffer, // The "meaningful" locking script Buffer (redeemScript for P2SH etc.)
  isSegwit: boolean, // Is it segwit?
  isP2SH: boolean, // Is it P2SH?
  isP2WSH: boolean // Is it P2WSH?
) => {
  finalScriptSig: Buffer | undefined;
  finalScriptWitness: Buffer | undefined;
};

// We use bitcoinjs-lib compatible Psbt interface.
// The actual Psbt class will be provided externally (from the consumer)
// or we define a minimal interface for what we need.
interface PsbtLike {
  addInput(input: PsbtInputExtended): void;
  addOutput(output: { script: Buffer; value: number }): void;
  setLocktime(locktime: number): void;
  locktime: number;
  data: { inputs: PsbtInput[] };
  txInputs: Array<{ sequence: number; index: number }>;
  validateSignaturesOfInput(
    index: number,
    validator: (pubkey: Buffer, msghash: Buffer, signature: Buffer) => boolean
  ): boolean;
  finalizeInput(index: number, finalScriptsFunc?: FinalScriptsFunc): void;
  signInput(index: number, signer: { publicKey: Buffer; sign(hash: Buffer): Buffer }): void;
  signInputHD(index: number, hdNode: { publicKey: Buffer; fingerprint: Buffer; derivePath(path: string): { publicKey: Buffer; sign(hash: Buffer): Buffer } }): void;
  signAllInputsHD(hdNode: { publicKey: Buffer; fingerprint: Buffer; derivePath(path: string): { publicKey: Buffer; sign(hash: Buffer): Buffer } }): void;
}

function reverseBuffer(buffer: Buffer): Buffer {
  if (buffer.length < 1) return buffer;
  let j = buffer.length - 1;
  let tmp = 0;
  for (let i = 0; i < buffer.length / 2; i++) {
    tmp = buffer[i]!;
    buffer[i] = buffer[j]!;
    buffer[j] = tmp;
    j--;
  }
  return buffer;
}
function witnessStackToScriptWitness(witness: Buffer[]): Buffer {
  let buffer = Buffer.allocUnsafe(0);

  function writeSlice(slice: Buffer): void {
    buffer = Buffer.concat([buffer, Buffer.from(slice)]);
  }

  function writeVarInt(i: number): void {
    const currentLen = buffer.length;
    const varintLen = varintEncodingLength(i);

    buffer = Buffer.concat([buffer, Buffer.allocUnsafe(varintLen)]);
    varintEncode(i, buffer, currentLen);
  }

  function writeVarSlice(slice: Buffer): void {
    writeVarInt(slice.length);
    writeSlice(slice);
  }

  function writeVector(vector: Buffer[]): void {
    writeVarInt(vector.length);
    vector.forEach(writeVarSlice);
  }

  writeVector(witness);

  return buffer;
}

export function finalScriptsFuncFactory(
  scriptSatisfaction: Buffer,
  network: Network
): FinalScriptsFunc {
  const net = toBtcSignerNetwork(network);
  const finalScriptsFunc: FinalScriptsFunc = (
    _index,
    _input,
    lockingScript /*witnessScript or redeemScript*/,
    isSegwit,
    isP2SH,
    _isP2WSH
  ) => {
    let finalScriptWitness: Buffer | undefined;
    let finalScriptSig: Buffer | undefined;
    //p2wsh
    if (isSegwit && !isP2SH) {
      const innerPayment = { input: scriptSatisfaction, output: lockingScript } as any;
      const payment = toPayment(
        btc.p2wsh(innerPayment, net) as Record<string, unknown>
      );
      if (!payment.witness)
        throw new Error(`Error: p2wsh failed producing a witness`);
      finalScriptWitness = witnessStackToScriptWitness(payment.witness);
    }
    //p2sh-p2wsh
    else if (isSegwit && isP2SH) {
      const innerPayment = { input: scriptSatisfaction, output: lockingScript } as any;
      const wshPayment = btc.p2wsh(innerPayment, net);
      const payment = toPayment(
        btc.p2sh(wshPayment, net) as Record<string, unknown>
      );
      if (!payment.witness)
        throw new Error(`Error: p2sh-p2wsh failed producing a witness`);
      finalScriptWitness = witnessStackToScriptWitness(payment.witness);
      finalScriptSig = payment.input;
    }
    //p2sh
    else {
      const innerPayment = { input: scriptSatisfaction, output: lockingScript } as any;
      finalScriptSig = toPayment(
        btc.p2sh(innerPayment, net) as Record<string, unknown>
      ).input;
    }
    return {
      finalScriptWitness,
      finalScriptSig
    };
  };
  return finalScriptsFunc;
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
  value?: number;
  sequence: number | undefined;
  locktime: number | undefined;
  keysInfo: KeyInfo[];
  scriptPubKey: Buffer;
  isSegwit: boolean;
  /** for taproot **/
  tapInternalKey?: Buffer | undefined;
  witnessScript: Buffer | undefined;
  redeemScript: Buffer | undefined;
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
    const outputScript = out.script ? Buffer.from(out.script) : undefined;
    if (!outputScript)
      throw new Error(
        `Error: could not extract outputScript for txHex ${txHex} and vout ${vout}`
      );
    if (Buffer.compare(outputScript, scriptPubKey) !== 0)
      throw new Error(
        `Error: txHex ${txHex} for vout ${vout} does not correspond to scriptPubKey ${scriptPubKey}`
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
      if (Number(out.amount) !== value)
        throw new Error(
          `Error: value for ${txHex} and vout ${vout} does not correspond to ${value}`
        );
    } else {
      value = Number(out.amount);
    }
  }
  if (txId === undefined || !value)
    throw new Error(
      `Error: txHex+vout required. Alternatively, but ONLY for Segwit inputs, txId+value can also be passed.`
    );

  if (locktime) {
    if (psbt.locktime && psbt.locktime !== locktime)
      throw new Error(
        `Error: transaction locktime was already set with a different value: ${locktime} != ${psbt.locktime}`
      );
    // nLockTime only works if at least one of the transaction inputs has an
    // nSequence value that is below 0xffffffff. Let's make sure that at least
    // this input's sequence < 0xffffffff
    if (sequence === undefined) {
      //NOTE: if sequence is undefined, bitcoinjs-lib uses 0xffffffff as default
      sequence = rbf ? 0xfffffffd : 0xfffffffe;
    } else if (sequence > 0xfffffffe) {
      throw new Error(
        `Error: incompatible sequence: ${sequence} and locktime: ${locktime}`
      );
    }
    if (sequence === undefined && rbf) sequence = 0xfffffffd;
    psbt.setLocktime(locktime);
  } else {
    if (sequence === undefined) {
      if (rbf) sequence = 0xfffffffd;
      else sequence = 0xffffffff;
    }
  }

  const input: PsbtInputExtended = {
    hash: reverseBuffer(Buffer.from(txId, 'hex')),
    index: vout
  };
  if (txHex !== undefined) {
    input.nonWitnessUtxo = Buffer.from(hex.decode(txHex));
  }

  if (tapInternalKey) {
    //Taproot
    const tapBip32Derivation = keysInfo
      .filter(
        (keyInfo: KeyInfo) =>
          keyInfo.pubkey && keyInfo.masterFingerprint && keyInfo.path
      )
      .map((keyInfo: KeyInfo): TapBip32Derivation => {
        const pubkey = keyInfo.pubkey;
        if (!pubkey)
          throw new Error(`key ${keyInfo.keyExpression} missing pubkey`);
        return {
          masterFingerprint: keyInfo.masterFingerprint!,
          pubkey,
          path: keyInfo.path!,
          leafHashes: [] // TODO: Empty array for tr(KEY) taproot key spend - this is the only type currently supported
        };
      });

    if (tapBip32Derivation.length)
      input.tapBip32Derivation = tapBip32Derivation;
    input.tapInternalKey = tapInternalKey;

    //TODO: currently only single-key taproot supported.
    if (tapBip32Derivation.length > 1)
      throw new Error('Only single key taproot inputs are currently supported');
  } else {
    const bip32Derivation = keysInfo
      .filter(
        (keyInfo: KeyInfo) =>
          keyInfo.pubkey && keyInfo.masterFingerprint && keyInfo.path
      )
      .map((keyInfo: KeyInfo): Bip32Derivation => {
        const pubkey = keyInfo.pubkey;
        if (!pubkey)
          throw new Error(`key ${keyInfo.keyExpression} missing pubkey`);
        return {
          masterFingerprint: keyInfo.masterFingerprint!,
          pubkey,
          path: keyInfo.path!
        };
      });
    if (bip32Derivation.length) input.bip32Derivation = bip32Derivation;
  }
  if (isSegwit && txHex !== undefined) {
    //There's no need to put both witnessUtxo and nonWitnessUtxo
    input.witnessUtxo = { script: scriptPubKey, value };
  }
  if (sequence !== undefined) input.sequence = sequence;

  if (witnessScript) input.witnessScript = witnessScript;
  if (redeemScript) input.redeemScript = redeemScript;

  psbt.addInput(input);
  return psbt.data.inputs.length - 1;
}

export type { PsbtInput, Bip32Derivation, TapBip32Derivation, PsbtLike };
