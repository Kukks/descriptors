// Copyright (c) 2025 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import * as btc from '@scure/btc-signer';
const { Script, OP, ScriptNum } = btc;
import { hex } from '@scure/base';

// ---- Varint encoding ----

export function varintEncodingLength(n: number): number {
  if (n < 0xfd) return 1;
  if (n <= 0xffff) return 3;
  if (n <= 0xffffffff) return 5;
  return 9;
}

// ---- Script helpers ----

// Build set of valid btc-signer opcode names
const SIGNER_OP_NAMES = new Set<string>();
for (const key of Object.keys(OP)) {
  if (isNaN(Number(key))) {
    SIGNER_OP_NAMES.add(key);
  }
}

function asmTokenToSignerOp(token: string): string | number | undefined {
  if (token === 'OP_0' || token === 'OP_FALSE') return 'OP_0';
  if (token === 'OP_1' || token === 'OP_TRUE') return 'OP_1';
  for (let i = 2; i <= 16; i++) {
    if (token === `OP_${i}`) return `OP_${i}`;
  }
  if (token === '1NEGATE' || token === 'OP_1NEGATE') return '1NEGATE';

  if (token.startsWith('OP_')) {
    const stripped = token.slice(3);
    if (SIGNER_OP_NAMES.has(stripped)) return stripped;
  }
  if (SIGNER_OP_NAMES.has(token)) return token;

  return undefined;
}

/**
 * Convert ASM string to script bytes.
 * Applies minimal encoding rules matching bitcoinjs-lib: single-byte data
 * pushes 0x01-0x10 are converted to OP_1-OP_16, and empty data is OP_0.
 */
export function fromASM(asm: string): Uint8Array {
  const tokens = asm.trim().split(/\s+/);
  const scriptElements: (string | Uint8Array | number)[] = [];

  for (const token of tokens) {
    if (token === '') continue;
    const op = asmTokenToSignerOp(token);
    if (op !== undefined) {
      scriptElements.push(op);
    } else {
      try {
        const data = hex.decode(token);
        if (data.length === 0) {
          scriptElements.push('OP_0');
        } else if (data.length === 1 && data[0]! >= 1 && data[0]! <= 16) {
          scriptElements.push(`OP_${data[0]!}`);
        } else if (data.length === 1 && data[0] === 0x81) {
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
  return Script.encode(scriptElements as any);
}

/**
 * Decompile script to array of opcodes and data.
 * Returns opcode numbers and Uint8Array data pushes.
 */
export function decompileScript(
  script: Uint8Array
): (number | Uint8Array)[] | null {
  try {
    const decoded = Script.decode(script);
    return decoded.map(item => {
      if (typeof item === 'number') return item;
      if (item instanceof Uint8Array) return item;
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
  return hex.encode(encoded);
}

// ---- Byte helpers ----

/** Read a 4-byte big-endian unsigned integer from a Uint8Array. */
export function readUInt32BE(buf: Uint8Array): number {
  return ((buf[0]! << 24) | (buf[1]! << 16) | (buf[2]! << 8) | buf[3]!) >>> 0;
}
