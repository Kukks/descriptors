// Copyright (c) 2025 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

// Compatibility layer for migrating from bitcoinjs-lib to scure/noble

import * as btc from '@scure/btc-signer';
const { Script, OP, ScriptNum } = btc;
import { hex } from '@scure/base';
import {
  hash160 as _hash160,
  sha256x2,
  tagSchnorr,
  concatBytes,
  compareBytes as _compareBytes,
  equalBytes as _equalBytes,
  tapTweak as _tapTweak,
  taprootTweakPubkey as _taprootTweakPubkey,
  taprootTweakPrivKey as _taprootTweakPrivKey
} from '@scure/btc-signer/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';

// ---- Network ----

export interface Network {
  messagePrefix: string;
  bech32: string;
  bip32: { public: number; private: number };
  pubKeyHash: number;
  scriptHash: number;
  wif: number;
}

export const networks: {
  bitcoin: Network;
  testnet: Network;
  regtest: Network;
} = {
  bitcoin: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'bc',
    bip32: { public: 0x0488b21e, private: 0x0488ade4 },
    pubKeyHash: 0x00,
    scriptHash: 0x05,
    wif: 0x80
  },
  testnet: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'tb',
    bip32: { public: 0x043587cf, private: 0x04358394 },
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef
  },
  regtest: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'bcrt',
    bip32: { public: 0x043587cf, private: 0x04358394 },
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef
  }
};

/** Convert our Network to the format expected by @scure/btc-signer */
export function toBtcSignerNetwork(network: Network) {
  return {
    bech32: network.bech32,
    pubKeyHash: network.pubKeyHash,
    scriptHash: network.scriptHash,
    wif: network.wif
  };
}

// ---- Payment ----

/**
 * Payment interface compatible with btc-signer.
 */
export interface Payment {
  type?: string;
  address?: string;
  script?: Buffer;
  redeem?: Payment;
  witness?: Buffer[];
  input?: Buffer;
  internalPubkey?: Buffer;
  redeemScript?: Buffer;
  witnessScript?: Buffer;
  hash?: Buffer;
  pubkey?: Buffer;
}

/**
 * Convert a btc-signer payment result to our Payment interface.
 */
export function toPayment(result: Record<string, unknown>): Payment {
  const p: Payment = {};
  if (result['type'] !== undefined) p.type = result['type'] as string;
  if (result['address'] !== undefined) p.address = result['address'] as string;
  if (result['script'] !== undefined) {
    p.script = Buffer.from(result['script'] as Uint8Array);
  }
  if (result['hash'] !== undefined) p.hash = Buffer.from(result['hash'] as Uint8Array);
  if (result['redeemScript'] !== undefined) p.redeemScript = Buffer.from(result['redeemScript'] as Uint8Array);
  if (result['witnessScript'] !== undefined) p.witnessScript = Buffer.from(result['witnessScript'] as Uint8Array);
  if (result['tapInternalKey'] !== undefined) p.internalPubkey = Buffer.from(result['tapInternalKey'] as Uint8Array);
  if (result['tweakedPubkey'] !== undefined) p.pubkey = Buffer.from(result['tweakedPubkey'] as Uint8Array);
  return p;
}

// ---- Buffer / Uint8Array helpers ----

export function toBuffer(data: Uint8Array): Buffer {
  return Buffer.from(data);
}

export function toUint8Array(data: Buffer | Uint8Array): Uint8Array {
  if (data instanceof Uint8Array && !(data instanceof Buffer)) return data;
  return new Uint8Array(data);
}

// ---- Hash functions ----

export function hash160(data: Uint8Array): Buffer {
  return Buffer.from(_hash160(data));
}

export function hash256(data: Uint8Array): Buffer {
  return Buffer.from(sha256x2(data));
}

export { sha256, ripemd160 };

/**
 * BIP340 tagged hash
 */
export function taggedHash(tag: string, ...messages: Uint8Array[]): Buffer {
  return Buffer.from(tagSchnorr(tag, ...messages));
}

/**
 * Compute tapTweakHash (for Taproot key-path tweaking)
 * _tapTweak returns a bigint; we convert it to a 32-byte big-endian Buffer.
 */
export function tapTweakHash(
  pubkey: Uint8Array,
  h?: Uint8Array
): Buffer {
  const tweakBigint = _tapTweak(pubkey, h ?? new Uint8Array(0));
  // Convert bigint to 32-byte big-endian buffer
  const hexStr = tweakBigint.toString(16).padStart(64, '0');
  return Buffer.from(hexStr, 'hex');
}

export const taprootTweakPubkey = _taprootTweakPubkey;
export const taprootTweakPrivKey = _taprootTweakPrivKey;

// ---- Varint encoding (replaces varuint-bitcoin) ----

export function varintEncodingLength(n: number): number {
  if (n < 0xfd) return 1;
  if (n <= 0xffff) return 3;
  if (n <= 0xffffffff) return 5;
  return 9;
}

export function varintEncode(
  n: number,
  buffer: Buffer,
  offset: number
): number {
  if (n < 0xfd) {
    buffer[offset] = n;
    return 1;
  }
  if (n <= 0xffff) {
    buffer[offset] = 0xfd;
    buffer.writeUInt16LE(n, offset + 1);
    return 3;
  }
  if (n <= 0xffffffff) {
    buffer[offset] = 0xfe;
    buffer.writeUInt32LE(n, offset + 1);
    return 5;
  }
  buffer[offset] = 0xff;
  buffer.writeUInt32LE(n >>> 0, offset + 1);
  buffer.writeUInt32LE((n / 0x100000000) | 0, offset + 5);
  return 9;
}

// ---- Taproot helpers ----

/**
 * Detect if a PSBT input is a Taproot input.
 * Replaces `isTaprootInput` from `bitcoinjs-lib/src/psbt/bip371`
 */
export function isTaprootInput(input: Record<string, unknown>): boolean {
  return !!(
    input['tapInternalKey'] ||
    input['tapMerkleRoot'] ||
    (input['tapLeafScript'] &&
      Array.isArray(input['tapLeafScript']) &&
      (input['tapLeafScript'] as unknown[]).length > 0) ||
    (input['tapBip32Derivation'] &&
      Array.isArray(input['tapBip32Derivation']) &&
      (input['tapBip32Derivation'] as unknown[]).length > 0) ||
    input['tapKeySig'] ||
    (input['tapScriptSig'] &&
      Array.isArray(input['tapScriptSig']) &&
      (input['tapScriptSig'] as unknown[]).length > 0)
  );
}

// ---- Script / ASM helpers ----

// Build set of valid btc-signer opcode names
const SIGNER_OP_NAMES = new Set<string>();
for (const key of Object.keys(OP)) {
  if (isNaN(Number(key))) {
    SIGNER_OP_NAMES.add(key);
  }
}

function asmTokenToSignerOp(token: string): string | number | undefined {
  // Handle OP_0..OP_16 (numbers)
  if (token === 'OP_0' || token === 'OP_FALSE') return 'OP_0';
  if (token === 'OP_1' || token === 'OP_TRUE') return 'OP_1';
  for (let i = 2; i <= 16; i++) {
    if (token === `OP_${i}`) return `OP_${i}`;
  }
  if (token === '1NEGATE' || token === 'OP_1NEGATE') return '1NEGATE';

  // Named opcode with OP_ prefix: OP_DUP -> DUP
  if (token.startsWith('OP_')) {
    const stripped = token.slice(3);
    if (SIGNER_OP_NAMES.has(stripped)) return stripped;
  }
  // Already a btc-signer name: DUP, CHECKSIG, etc.
  if (SIGNER_OP_NAMES.has(token)) return token;

  return undefined;
}

/**
 * Convert ASM string to script buffer.
 * Replaces `bscript.fromASM(asm)` from bitcoinjs-lib.
 *
 * Applies minimal encoding rules matching bitcoinjs-lib: single-byte data
 * pushes 0x01-0x10 are converted to OP_1-OP_16, and empty data is OP_0.
 */
export function fromASM(asm: string): Buffer {
  const tokens = asm.trim().split(/\s+/);
  const scriptElements: (string | Uint8Array | number)[] = [];

  for (const token of tokens) {
    if (token === '') continue;
    const op = asmTokenToSignerOp(token);
    if (op !== undefined) {
      scriptElements.push(op);
    } else {
      // Treat as hex data push
      try {
        const data = hex.decode(token);
        // Apply minimal encoding: single-byte data 0x01-0x10 → OP_1-OP_16,
        // empty data → OP_0.  This matches bitcoinjs-lib's compile behavior.
        if (data.length === 0) {
          scriptElements.push('OP_0');
        } else if (data.length === 1 && data[0]! >= 1 && data[0]! <= 16) {
          scriptElements.push(`OP_${data[0]!}`);
        } else if (data.length === 1 && data[0] === 0x81) {
          // 0x81 = -1 → OP_1NEGATE
          scriptElements.push('1NEGATE');
        } else {
          scriptElements.push(data);
        }
      } catch {
        throw new Error(`Error: unknown ASM token: ${token}`);
      }
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return Buffer.from(Script.encode(scriptElements as any));
}

/**
 * Decompile script to array of opcodes and data.
 * Replaces `bscript.decompile(script)` from bitcoinjs-lib.
 * Returns opcode numbers and Buffer data pushes.
 */
export function decompileScript(
  script: Buffer | Uint8Array
): (number | Buffer)[] | null {
  try {
    const decoded = Script.decode(toUint8Array(script));
    return decoded.map(item => {
      if (typeof item === 'number') return item;
      if (item instanceof Uint8Array) return Buffer.from(item);
      // String opcode: convert to number
      const opNum = (OP as unknown as Record<string, number>)[item as string];
      if (opNum !== undefined) return opNum;
      return item as unknown as number;
    });
  } catch {
    return null;
  }
}

/**
 * Encode a number for use in ASM.
 * Replaces `bscript.number.encode()` from bitcoinjs-lib.
 * Returns a hex string for non-zero numbers, "OP_0" for zero.
 */
export function numberEncodeAsm(number: number): string {
  if (Number.isSafeInteger(number) === false) {
    throw new Error(`Error: invalid number ${number}`);
  }
  if (number === 0) {
    return 'OP_0';
  }
  const encoded = ScriptNum(6).encode(BigInt(number));
  return Buffer.from(encoded).toString('hex');
}

// ---- Byte comparison helpers ----

export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  // Use a proper lexicographic compare (Buffer.compare compatible)
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i]! < b[i]!) return -1;
    if (a[i]! > b[i]!) return 1;
  }
  if (a.length < b.length) return -1;
  if (a.length > b.length) return 1;
  return 0;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return _equalBytes(a, b);
}

// ---- Fingerprint number <-> Buffer conversion ----

export function fingerprintToBuffer(fp: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(fp, 0);
  return buf;
}

export function bufferToFingerprint(buf: Buffer | Uint8Array): number {
  if (buf instanceof Buffer) return buf.readUInt32BE(0);
  return (buf[0]! << 24) | (buf[1]! << 16) | (buf[2]! << 8) | buf[3]!;
}

// ---- BIP32 path string <-> number[] conversion ----

export function pathStringToArray(pathStr: string): number[] {
  return btc.bip32Path(pathStr);
}

const HARDENED = 0x80000000;
export function pathArrayToString(path: number[]): string {
  return (
    'm/' +
    path
      .map(v => (v >= HARDENED ? `${v - HARDENED}'` : `${v}`))
      .join('/')
  );
}

// ---- Address helpers ----

/**
 * Convert an address to its output script.
 * Replaces `address.toOutputScript(addr, network)` from bitcoinjs-lib.
 */
export function addressToOutputScript(addr: string, network: Network): Buffer {
  const net = toBtcSignerNetwork(network);
  const decoded = btc.Address(net).decode(addr);
  return Buffer.from(btc.OutScript.encode(decoded));
}

/**
 * Detect output script type from raw script bytes.
 */
export function getOutputScriptType(
  script: Uint8Array
): { type: string; [key: string]: unknown } | null {
  try {
    return btc.OutScript.decode(script) as { type: string; [key: string]: unknown };
  } catch {
    return null;
  }
}

// ---- PartialSig type (previously from bip174) ----

export interface PartialSig {
  pubkey: Buffer;
  signature: Buffer;
}

// Re-export useful items
export { OP, Script, ScriptNum };
export { hex, concatBytes };
export { tagSchnorr };
export { btc };
