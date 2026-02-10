// Copyright (c) 2025 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

// Pure JS/TS implementations of ECPairAPI and BIP32API using
// @noble/curves, @scure/bip32, @noble/hashes, and @scure/base.
// These conform to the interfaces defined in ../../src/types.ts.

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { HDKey } from '@scure/bip32';
import { sha256 } from '@noble/hashes/sha2.js';
import { base58check } from '@scure/base';
import type {
  ECPairInterface,
  ECPairAPI,
  BIP32Interface,
  BIP32API
} from '../../src/types.js';
import { networks, type Network } from '../../src/compat.js';

export { networks };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const bs58check = base58check(sha256);

const DEFAULT_NETWORK: Network = networks.bitcoin;

/** Convert a bigint to a 32-byte big-endian Buffer. */
function bigintTo32Bytes(n: bigint): Buffer {
  const hexStr = n.toString(16).padStart(64, '0');
  return Buffer.from(hexStr, 'hex');
}

// ---------------------------------------------------------------------------
// WIF encode / decode
// ---------------------------------------------------------------------------

function encodeWIF(
  privateKey: Buffer,
  compressed: boolean,
  network: Network
): string {
  const prefix = Buffer.alloc(1, network.wif);
  const payload = compressed
    ? Buffer.concat([prefix, privateKey, Buffer.from([0x01])])
    : Buffer.concat([prefix, privateKey]);
  return bs58check.encode(payload);
}

function decodeWIF(
  wif: string,
  network?: Network | Network[]
): { privateKey: Buffer; compressed: boolean; network: Network } {
  const decoded = Buffer.from(bs58check.decode(wif));
  const version = decoded[0]!;

  // Determine matching network(s)
  const candidateNetworks = network
    ? Array.isArray(network)
      ? network
      : [network]
    : [networks.bitcoin, networks.testnet, networks.regtest];

  const matchedNetwork = candidateNetworks.find(n => n.wif === version);
  if (!matchedNetwork) {
    throw new Error(`Invalid network version`);
  }

  // Determine if compressed
  if (decoded.length === 34 && decoded[33] === 0x01) {
    return {
      privateKey: decoded.subarray(1, 33) as Buffer,
      compressed: true,
      network: matchedNetwork
    };
  } else if (decoded.length === 33) {
    return {
      privateKey: decoded.subarray(1, 33) as Buffer,
      compressed: false,
      network: matchedNetwork
    };
  } else {
    throw new Error('Invalid WIF payload length');
  }
}

// ---------------------------------------------------------------------------
// ECPair implementation
// ---------------------------------------------------------------------------

function createECPair(
  privKey: Buffer | undefined,
  pubKeyInput: Buffer | undefined,
  compressed: boolean,
  network: Network
): ECPairInterface {
  let pubKey: Buffer;

  if (privKey) {
    const rawPub = secp256k1.getPublicKey(privKey, compressed);
    pubKey = Buffer.from(rawPub);
  } else if (pubKeyInput) {
    // Normalise to the requested compression
    const point = secp256k1.Point.fromHex(pubKeyInput.toString('hex'));
    pubKey = Buffer.from(point.toBytes(compressed));
  } else {
    throw new Error('Either privateKey or publicKey must be provided');
  }

  // Build the object conditionally so that `privateKey` is only present
  // when defined (satisfies exactOptionalPropertyTypes).
  const base = {
    publicKey: pubKey,
    compressed,
    network,

    sign(hash: Buffer): Buffer {
      if (!privKey) throw new Error('Missing private key');
      // v2: sign() returns compact Uint8Array directly
      return Buffer.from(secp256k1.sign(hash, privKey));
    },

    verify(hash: Buffer, signature: Buffer): boolean {
      return secp256k1.verify(signature, hash, pubKey);
    },

    toWIF(): string {
      if (!privKey) throw new Error('Missing private key');
      return encodeWIF(privKey, compressed, network);
    },

    tweak(t: Buffer): ECPairInterface {
      const tweakBigint = BigInt('0x' + t.toString('hex'));
      const n = secp256k1.Point.CURVE().n;

      if (privKey) {
        const privBigint = BigInt('0x' + privKey.toString('hex'));
        const newPrivBigint = (privBigint + tweakBigint) % n;
        if (newPrivBigint === 0n) {
          throw new Error('Tweaked private key is zero');
        }
        const newPrivKey = bigintTo32Bytes(newPrivBigint);
        return createECPair(newPrivKey, undefined, compressed, network);
      } else {
        // Public-key-only tweak: P' = P + t*G
        const G = secp256k1.Point.BASE;
        const tweakPoint = G.multiply(tweakBigint);
        const pubPoint = secp256k1.Point.fromHex(pubKey.toString('hex'));
        const tweakedPoint = pubPoint.add(tweakPoint);
        return createECPair(
          undefined,
          Buffer.from(tweakedPoint.toBytes(compressed)),
          compressed,
          network
        );
      }
    }
  };

  if (privKey) {
    return Object.assign(base, { privateKey: privKey }) as ECPairInterface;
  }
  return base as ECPairInterface;
}

export const ECPair: ECPairAPI = {
  fromPublicKey(
    publicKey: Buffer,
    options?: { network?: Network; compressed?: boolean }
  ): ECPairInterface {
    const compressed = options?.compressed !== false;
    const network = options?.network ?? DEFAULT_NETWORK;
    return createECPair(undefined, publicKey, compressed, network);
  },

  fromPrivateKey(
    privateKey: Buffer,
    options?: { network?: Network; compressed?: boolean }
  ): ECPairInterface {
    const compressed = options?.compressed !== false;
    const network = options?.network ?? DEFAULT_NETWORK;
    return createECPair(privateKey, undefined, compressed, network);
  },

  fromWIF(wif: string, network?: Network | Network[]): ECPairInterface {
    const { privateKey, compressed, network: net } = decodeWIF(wif, network);
    return createECPair(privateKey, undefined, compressed, net);
  },

  makeRandom(options?: {
    network?: Network;
    compressed?: boolean;
  }): ECPairInterface {
    const privKey = Buffer.from(secp256k1.utils.randomSecretKey());
    const compressed = options?.compressed !== false;
    const network = options?.network ?? DEFAULT_NETWORK;
    return createECPair(privKey, undefined, compressed, network);
  },

  isPoint(p: Buffer | Uint8Array): boolean {
    try {
      secp256k1.Point.fromHex(Buffer.from(p).toString('hex'));
      return true;
    } catch {
      return false;
    }
  }
};

// ---------------------------------------------------------------------------
// BIP32 implementation
// ---------------------------------------------------------------------------

/** Map a Network to the versions object expected by @scure/bip32's HDKey. */
function networkToVersions(
  network: Network
): { public: number; private: number } {
  return { public: network.bip32.public, private: network.bip32.private };
}

function wrapHDKey(hdkey: HDKey, network: Network): BIP32Interface {
  const versions = networkToVersions(network);

  // Build the base object without privateKey, then conditionally add it.
  // This satisfies exactOptionalPropertyTypes.
  const base = {
    get publicKey(): Buffer {
      if (!hdkey.publicKey) throw new Error('Missing public key');
      return Buffer.from(hdkey.publicKey);
    },

    get chainCode(): Buffer {
      if (!hdkey.chainCode) throw new Error('Missing chain code');
      return Buffer.from(hdkey.chainCode);
    },

    get fingerprint(): Buffer {
      // HDKey.fingerprint is a number (4-byte big-endian unsigned int)
      const buf = Buffer.alloc(4);
      buf.writeUInt32BE(hdkey.fingerprint >>> 0, 0);
      return buf;
    },

    get depth(): number {
      return hdkey.depth;
    },

    get index(): number {
      return hdkey.index;
    },

    get parentFingerprint(): number {
      return hdkey.parentFingerprint;
    },

    network,

    derivePath(path: string): BIP32Interface {
      // @scure/bip32 requires paths to start with "m" or "M"
      // Old bip32 package accepted relative paths like "0'/1'/0'"
      const normalizedPath =
        path.startsWith('m') || path.startsWith('M') ? path : `m/${path}`;
      return wrapHDKey(hdkey.derive(normalizedPath), network);
    },

    derive(index: number): BIP32Interface {
      return wrapHDKey(hdkey.deriveChild(index), network);
    },

    deriveHardened(index: number): BIP32Interface {
      return wrapHDKey(hdkey.deriveChild(index + 0x80000000), network);
    },

    neutered(): BIP32Interface {
      // Create a public-only HDKey via the public extended key
      const xpub = hdkey.publicExtendedKey;
      const neuteredKey = HDKey.fromExtendedKey(xpub, versions);
      return wrapHDKey(neuteredKey, network);
    },

    toBase58(): string {
      if (hdkey.privateKey) {
        return hdkey.privateExtendedKey;
      }
      return hdkey.publicExtendedKey;
    },

    sign(hash: Buffer): Buffer {
      if (!hdkey.privateKey) throw new Error('Missing private key');
      return Buffer.from(hdkey.sign(hash));
    },

    verify(hash: Buffer, signature: Buffer): boolean {
      return hdkey.verify(hash, signature);
    },

    isNeutered(): boolean {
      return !hdkey.privateKey;
    },

    toWIF(): string {
      if (!hdkey.privateKey) {
        throw new Error('Missing private key');
      }
      return encodeWIF(Buffer.from(hdkey.privateKey), true, network);
    }
  };

  if (hdkey.privateKey) {
    return Object.defineProperty(base, 'privateKey', {
      get(): Buffer {
        return Buffer.from(hdkey.privateKey!);
      },
      enumerable: true,
      configurable: true
    }) as BIP32Interface;
  }

  return base as BIP32Interface;
}

export const BIP32: BIP32API = {
  fromBase58(base58: string, network?: Network): BIP32Interface {
    const net = network ?? DEFAULT_NETWORK;
    const versions = networkToVersions(net);
    const hdkey = HDKey.fromExtendedKey(base58, versions);
    return wrapHDKey(hdkey, net);
  },

  fromPublicKey(
    publicKey: Buffer,
    chainCode: Buffer,
    network?: Network
  ): BIP32Interface {
    const net = network ?? DEFAULT_NETWORK;
    const versions = networkToVersions(net);
    // Manually serialise the public extended key in base58check format.
    //
    // xpub format (78 bytes):
    //   version (4) + depth (1) + parentFingerprint (4) + index (4) +
    //   chainCode (32) + publicKey (33)
    const buf = Buffer.alloc(78);
    buf.writeUInt32BE(versions.public, 0); // version
    buf[4] = 0; // depth
    buf.writeUInt32BE(0, 5); // parent fingerprint
    buf.writeUInt32BE(0, 9); // index
    chainCode.copy(buf, 13);
    publicKey.copy(buf, 45);

    const xpub = bs58check.encode(buf);
    const hdkey = HDKey.fromExtendedKey(xpub, versions);
    return wrapHDKey(hdkey, net);
  },

  fromPrivateKey(
    privateKey: Buffer,
    chainCode: Buffer,
    network?: Network
  ): BIP32Interface {
    const net = network ?? DEFAULT_NETWORK;
    const versions = networkToVersions(net);

    // xprv format (78 bytes):
    //   version (4) + depth (1) + parentFingerprint (4) + index (4) +
    //   chainCode (32) + 0x00 (1) + privateKey (32)
    const buf = Buffer.alloc(78);
    buf.writeUInt32BE(versions.private, 0); // version
    buf[4] = 0; // depth
    buf.writeUInt32BE(0, 5); // parent fingerprint
    buf.writeUInt32BE(0, 9); // index
    chainCode.copy(buf, 13);
    buf[45] = 0x00; // padding byte before private key
    privateKey.copy(buf, 46);

    const xprv = bs58check.encode(buf);
    const hdkey = HDKey.fromExtendedKey(xprv, versions);
    return wrapHDKey(hdkey, net);
  },

  fromSeed(seed: Buffer, network?: Network): BIP32Interface {
    const net = network ?? DEFAULT_NETWORK;
    const versions = networkToVersions(net);
    const hdkey = HDKey.fromMasterSeed(seed, versions);
    return wrapHDKey(hdkey, net);
  }
};
