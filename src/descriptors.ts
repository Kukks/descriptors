// Copyright (c) 2025 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import memoize from 'lodash.memoize';
import * as btc from '@scure/btc-signer';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { schnorr } from '@noble/curves/secp256k1.js';

import {
  networks,
  Network,
  Payment,
  toPayment,
  toBtcSignerNetwork,
  addressToOutputScript,
  getOutputScriptType,
  varintEncodingLength,
  decompileScript,
  hash160,
  OP
} from './compat.js';
import { sha256 } from '@noble/hashes/sha2.js';
import type {
  ECPairAPI,
  BIP32API,
  PartialSig,
  Preimage,
  TimeConstraints,
  Expansion,
  ExpansionMap,
  ParseKeyExpression
} from './types.js';

import { finalScriptsFuncFactory, updatePsbt } from './psbt.js';
import type { PsbtLike } from './psbt.js';
import { DescriptorChecksum } from './checksum.js';

import { parseKeyExpression as globalParseKeyExpression } from './keyExpressions.js';
import * as RE from './re.js';
import {
  expandMiniscript as globalExpandMiniscript,
  miniscript2Script,
  satisfyMiniscript
} from './miniscript.js';

//See "Resource limitations" https://bitcoin.sipa.be/miniscript/
//https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2019-September/017306.html
const MAX_SCRIPT_ELEMENT_SIZE = 520;
const MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600;
const MAX_OPS_PER_SCRIPT = 201;

function countNonPushOnlyOPs(script: Buffer): number {
  const decompiled = decompileScript(script);
  if (!decompiled) throw new Error(`Error: cound not decompile ${script}`);
  return decompiled.filter(
    op => typeof op === 'number' && op > OP.OP_16
  ).length;
}

function vectorSize(someVector: Buffer[]): number {
  const length = someVector.length;

  return (
    varintEncodingLength(length) +
    someVector.reduce((sum, witness) => {
      return sum + varSliceSize(witness);
    }, 0)
  );
}

function varSliceSize(someScript: Buffer): number {
  const length = someScript.length;

  return varintEncodingLength(length) + length;
}

/**
 * Safe p2wsh wrapper: tries btc.p2wsh first, falls back to manual computation
 * when btc-signer rejects the inner script (e.g. complex miniscript).
 */
function safeP2wsh(
  innerScript: Uint8Array,
  net?: ReturnType<typeof toBtcSignerNetwork>
): Payment {
  try {
    return toPayment(
      btc.p2wsh(
        { type: 'unknown' as const, script: innerScript },
        net
      ) as Record<string, unknown>
    );
  } catch {
    // Manual computation: OP_0 <SHA256(script)>
    const scriptHash = sha256(innerScript);
    const outputScript = Buffer.from(
      btc.OutScript.encode({ type: 'wsh', hash: scriptHash })
    );
    const address = net
      ? btc.Address(net).encode({ type: 'wsh', hash: scriptHash })
      : undefined;
    return {
      script: outputScript,
      output: outputScript,
      witnessScript: Buffer.from(innerScript),
      ...(address ? { address } : {})
    };
  }
}

/**
 * Safe p2sh wrapper: tries btc.p2sh first, falls back to manual computation
 * when btc-signer rejects the inner payment.
 */
function safeP2sh(
  innerScript: Uint8Array,
  net?: ReturnType<typeof toBtcSignerNetwork>
): Payment {
  try {
    return toPayment(
      btc.p2sh(
        { type: 'unknown' as const, script: innerScript },
        net
      ) as Record<string, unknown>
    );
  } catch {
    // Manual computation: OP_HASH160 <HASH160(script)> OP_EQUAL
    const scriptHash = hash160(innerScript);
    const outputScript = Buffer.from(
      btc.OutScript.encode({ type: 'sh', hash: scriptHash })
    );
    const address = net
      ? btc.Address(net).encode({ type: 'sh', hash: scriptHash })
      : undefined;
    return {
      script: outputScript,
      output: outputScript,
      redeemScript: Buffer.from(innerScript),
      ...(address ? { address } : {})
    };
  }
}

/**
 * This function will typically return 73; since it assumes a signature size of
 * 72 bytes (this is the max size of a DER encoded signature) and it adds 1
 * extra byte for encoding its length
 */
function signatureSize(
  signature: PartialSig | 'DANGEROUSLY_USE_FAKE_SIGNATURES'
) {
  const length =
    signature === 'DANGEROUSLY_USE_FAKE_SIGNATURES'
      ? 72
      : signature.signature.length;
  return varintEncodingLength(length) + length;
}

/*
 * Returns a bare descriptor without checksum and particularized for a certain
 * index (if desc was a range descriptor)
 * @hidden
 */
function evaluate({
  descriptor,
  checksumRequired,
  index
}: {
  descriptor: string;
  checksumRequired: boolean;
  index?: number;
}): string {
  if (!descriptor) throw new Error('You must provide a descriptor.');

  const mChecksum = descriptor.match(String.raw`(${RE.reChecksum})$`);
  if (mChecksum === null && checksumRequired === true)
    throw new Error(`Error: descriptor ${descriptor} has not checksum`);
  //evaluatedDescriptor: a bare desc without checksum and particularized for a certain
  //index (if desc was a range descriptor)
  let evaluatedDescriptor = descriptor;
  if (mChecksum !== null) {
    const checksum = mChecksum[0].substring(1); //remove the leading #
    evaluatedDescriptor = descriptor.substring(
      0,
      descriptor.length - mChecksum[0].length
    );
    if (checksum !== DescriptorChecksum(evaluatedDescriptor)) {
      throw new Error(`Error: invalid descriptor checksum for ${descriptor}`);
    }
  }
  if (index !== undefined) {
    const mWildcard = evaluatedDescriptor.match(/\*/g);
    if (mWildcard && mWildcard.length > 0) {
      evaluatedDescriptor = evaluatedDescriptor.replaceAll(
        '*',
        index.toString()
      );
    } else
      throw new Error(
        `Error: index passed for non-ranged descriptor: ${descriptor}`
      );
  }
  return evaluatedDescriptor;
}

// Helper: parse sortedmulti(M, k1, k2,...)
function parseSortedMulti(inner: string) {
  const parts = inner.split(',').map(p => p.trim());
  if (parts.length < 2)
    throw new Error(
      `sortedmulti(): must contain M and at least one key: ${inner}`
    );

  const m = Number(parts[0]);
  if (!Number.isInteger(m) || m < 1 || m > 20)
    throw new Error(`sortedmulti(): invalid M=${parts[0]}`);

  const keyExpressions = parts.slice(1);
  if (keyExpressions.length < m)
    throw new Error(`sortedmulti(): M cannot exceed number of keys: ${inner}`);

  if (keyExpressions.length > 20)
    throw new Error(
      `sortedmulti(): descriptors support up to 20 keys (per BIP 380/383).`
    );

  return { m, keyExpressions };
}

/**
 * Constructs the necessary functions and classes for working with descriptors.
 *
 * Notably, it returns the {@link _Internal_.Output | `Output`} class, which
 * provides methods to create, sign, and finalize PSBTs based on descriptor
 * expressions.
 *
 * The Factory also returns utility methods like `expand` (detailed below)
 * and `parseKeyExpression` (see {@link ParseKeyExpression}).
 *
 * Additionally, for convenience, the function returns `BIP32` and `ECPair`.
 * These are compatible interfaces for managing BIP32 keys and
 * public/private key pairs respectively.
 *
 * @param {Object} params - An object with `ECPair` and `BIP32` factories.
 */
export function DescriptorsFactory({
  ECPair,
  BIP32
}: {
  ECPair: ECPairAPI;
  BIP32: BIP32API;
}) {
  const signatureValidator = (
    pubkey: Buffer,
    msghash: Buffer,
    signature: Buffer
  ): boolean => {
    if (pubkey.length === 32) {
      //x-only - Schnorr
      return schnorr.verify(signature, msghash, pubkey);
    } else {
      // ECDSA — bitcoinjs-lib v7 decodes DER to compact r||s (64 bytes)
      if (signature.length === 64) {
        return secp256k1.verify(signature, msghash, pubkey);
      }
      return secp256k1.verify(signature, msghash, pubkey, { format: 'der' });
    }
  };

  /**
   * Takes a string key expression (xpub, xprv, pubkey or wif) and parses it
   */
  const parseKeyExpression: ParseKeyExpression = ({
    keyExpression,
    isSegwit,
    isTaproot,
    network = networks.bitcoin
  }) => {
    return globalParseKeyExpression({
      keyExpression,
      network,
      ...(typeof isSegwit === 'boolean' ? { isSegwit } : {}),
      ...(typeof isTaproot === 'boolean' ? { isTaproot } : {}),
      ECPair,
      BIP32
    });
  };

  /**
   * Parses and analyzies a descriptor expression and destructures it into
   * {@link Expansion |its elemental parts}.
   *
   * @throws {Error} Throws an error if the descriptor cannot be parsed or does
   * not conform to the expected format.
   */
  function expand(params: {
    descriptor: string;
    index?: number;
    checksumRequired?: boolean;
    network?: Network;
    allowMiniscriptInP2SH?: boolean;
  }): Expansion;

  /**
   * @hidden
   * To be removed in version 3.0
   */
  function expand(params: {
    expression: string;
    index?: number;
    checksumRequired?: boolean;
    network?: Network;
    allowMiniscriptInP2SH?: boolean;
  }): Expansion;

  /**
   * @overload
   */
  function expand({
    descriptor,
    expression,
    index,
    checksumRequired = false,
    network = networks.bitcoin,
    allowMiniscriptInP2SH = false
  }: {
    descriptor?: string;
    expression?: string;
    index?: number;
    checksumRequired?: boolean;
    network?: Network;
    allowMiniscriptInP2SH?: boolean;
  }): Expansion {
    if (descriptor && expression)
      throw new Error(`expression param has been deprecated`);
    descriptor = descriptor || expression;
    if (!descriptor) throw new Error(`descriptor not provided`);
    let expandedExpression: string | undefined;
    let miniscript: string | undefined;
    let expansionMap: ExpansionMap | undefined;
    let isSegwit: boolean | undefined;
    let isTaproot: boolean | undefined;
    let expandedMiniscript: string | undefined;
    let payment: Payment | undefined;
    let witnessScript: Buffer | undefined;
    let redeemScript: Buffer | undefined;
    const isRanged = descriptor.indexOf('*') !== -1;
    const net = toBtcSignerNetwork(network);

    if (index !== undefined)
      if (!Number.isInteger(index) || index < 0)
        throw new Error(`Error: invalid index ${index}`);

    const canonicalExpression = evaluate({
      descriptor,
      ...(index !== undefined ? { index } : {}),
      checksumRequired
    });
    const isCanonicalRanged = canonicalExpression.indexOf('*') !== -1;

    //addr(ADDR)
    if (canonicalExpression.match(RE.reAddrAnchored)) {
      if (isRanged) throw new Error(`Error: addr() cannot be ranged`);
      const matchedAddress = canonicalExpression.match(RE.reAddrAnchored)?.[1];
      if (!matchedAddress)
        throw new Error(`Error: could not get an address in ${descriptor}`);
      let output: Buffer;
      try {
        output = addressToOutputScript(matchedAddress, network);
      } catch (e) {
        void e;
        throw new Error(`Error: invalid address ${matchedAddress}`);
      }
      // Detect output type using OutScript.decode
      const decoded = getOutputScriptType(output);
      if (!decoded) {
        throw new Error(`Error: invalid address ${matchedAddress}`);
      }
      const scriptType = decoded.type;
      // For addr() we already have the output script from addressToOutputScript.
      // We build a minimal Payment with the script and address.
      payment = {
        address: matchedAddress,
        script: output,
        output // compat alias
      };
      if (scriptType === 'pkh') {
        isSegwit = false;
        isTaproot = false;
      } else if (scriptType === 'sh') {
        isSegwit = true; // Assume SH is SH_WPKH
        isTaproot = false;
      } else if (scriptType === 'wpkh') {
        isSegwit = true;
        isTaproot = false;
      } else if (scriptType === 'wsh') {
        isSegwit = true;
        isTaproot = false;
      } else if (scriptType === 'tr') {
        isSegwit = true;
        isTaproot = true;
      } else {
        throw new Error(`Error: invalid address ${matchedAddress}`);
      }
    }
    //pk(KEY)
    else if (canonicalExpression.match(RE.rePkAnchored)) {
      isSegwit = false;
      isTaproot = false;
      const keyExpression = canonicalExpression.match(
        RE.reNonSegwitKeyExp
      )?.[0];
      if (!keyExpression)
        throw new Error(`Error: keyExpression could not me extracted`);
      if (canonicalExpression !== `pk(${keyExpression})`)
        throw new Error(`Error: invalid expression ${descriptor}`);
      expandedExpression = 'pk(@0)';
      const pKE = parseKeyExpression({ keyExpression, network, isSegwit });
      expansionMap = { '@0': pKE };
      if (!isCanonicalRanged) {
        const pubkey = pKE.pubkey;
        if (!pubkey)
          throw new Error(
            `Error: could not extract a pubkey from ${descriptor}`
          );
        payment = toPayment(btc.p2pk(pubkey, net) as Record<string, unknown>);
      }
    }
    //pkh(KEY) - legacy
    else if (canonicalExpression.match(RE.rePkhAnchored)) {
      isSegwit = false;
      isTaproot = false;
      const keyExpression = canonicalExpression.match(
        RE.reNonSegwitKeyExp
      )?.[0];
      if (!keyExpression)
        throw new Error(`Error: keyExpression could not me extracted`);
      if (canonicalExpression !== `pkh(${keyExpression})`)
        throw new Error(`Error: invalid expression ${descriptor}`);
      expandedExpression = 'pkh(@0)';
      const pKE = parseKeyExpression({ keyExpression, network, isSegwit });
      expansionMap = { '@0': pKE };
      if (!isCanonicalRanged) {
        const pubkey = pKE.pubkey;
        if (!pubkey)
          throw new Error(
            `Error: could not extract a pubkey from ${descriptor}`
          );
        payment = toPayment(btc.p2pkh(pubkey, net) as Record<string, unknown>);
      }
    }
    //sh(wpkh(KEY)) - nested segwit
    else if (canonicalExpression.match(RE.reShWpkhAnchored)) {
      isSegwit = true;
      isTaproot = false;
      const keyExpression = canonicalExpression.match(RE.reSegwitKeyExp)?.[0];
      if (!keyExpression)
        throw new Error(`Error: keyExpression could not me extracted`);
      if (canonicalExpression !== `sh(wpkh(${keyExpression}))`)
        throw new Error(`Error: invalid expression ${descriptor}`);
      expandedExpression = 'sh(wpkh(@0))';
      const pKE = parseKeyExpression({ keyExpression, network, isSegwit });
      expansionMap = { '@0': pKE };
      if (!isCanonicalRanged) {
        const pubkey = pKE.pubkey;
        if (!pubkey)
          throw new Error(
            `Error: could not extract a pubkey from ${descriptor}`
          );
        const wpkhPayment = btc.p2wpkh(pubkey, net);
        payment = toPayment(btc.p2sh(wpkhPayment, net) as Record<string, unknown>);
        redeemScript = payment.redeem?.output ?? (payment.redeemScript ? payment.redeemScript : undefined);
        if (!redeemScript) {
          // Construct redeemScript from wpkh output
          const wpkhP = toPayment(wpkhPayment as Record<string, unknown>);
          redeemScript = wpkhP.script ?? wpkhP.output;
        }
        if (!redeemScript)
          throw new Error(
            `Error: could not calculate redeemScript for ${descriptor}`
          );
      }
    }
    //wpkh(KEY) - native segwit
    else if (canonicalExpression.match(RE.reWpkhAnchored)) {
      isSegwit = true;
      isTaproot = false;
      const keyExpression = canonicalExpression.match(RE.reSegwitKeyExp)?.[0];
      if (!keyExpression)
        throw new Error(`Error: keyExpression could not me extracted`);
      if (canonicalExpression !== `wpkh(${keyExpression})`)
        throw new Error(`Error: invalid expression ${descriptor}`);
      expandedExpression = 'wpkh(@0)';
      const pKE = parseKeyExpression({ keyExpression, network, isSegwit });
      expansionMap = { '@0': pKE };
      if (!isCanonicalRanged) {
        const pubkey = pKE.pubkey;
        if (!pubkey)
          throw new Error(
            `Error: could not extract a pubkey from ${descriptor}`
          );
        payment = toPayment(btc.p2wpkh(pubkey, net) as Record<string, unknown>);
      }
    }
    // sortedmulti script expressions
    // sh(sortedmulti())
    else if (canonicalExpression.match(RE.reShSortedMultiAnchored)) {
      isSegwit = false;
      isTaproot = false;

      const inner = canonicalExpression.match(RE.reShSortedMultiAnchored)?.[1];
      if (!inner)
        throw new Error(`Error extracting sortedmulti() in ${descriptor}`);

      const { m, keyExpressions } = parseSortedMulti(inner);

      const pKEs = keyExpressions.map(k =>
        parseKeyExpression({ keyExpression: k, network, isSegwit: false })
      );

      const map: ExpansionMap = {};
      pKEs.forEach((pke, i) => (map['@' + i] = pke));
      expansionMap = map;

      expandedExpression =
        'sh(sortedmulti(' +
        [m, ...Object.keys(expansionMap).map(k => k)].join(',') +
        '))';

      if (!isCanonicalRanged) {
        const pubkeys = pKEs.map(p => {
          if (!p.pubkey) throw new Error(`Error: key has no pubkey`);
          return p.pubkey;
        });
        pubkeys.sort((a, b) => a.compare(b));

        const redeem = btc.p2ms(m, pubkeys, undefined);
        redeemScript = Buffer.from(redeem.script);

        payment = toPayment(btc.p2sh(redeem, net) as Record<string, unknown>);
      }
    }
    // wsh(sortedmulti())
    else if (canonicalExpression.match(RE.reWshSortedMultiAnchored)) {
      isSegwit = true;
      isTaproot = false;

      const inner = canonicalExpression.match(RE.reWshSortedMultiAnchored)?.[1];
      if (!inner)
        throw new Error(`Error extracting sortedmulti() in ${descriptor}`);

      const { m, keyExpressions } = parseSortedMulti(inner);

      const pKEs = keyExpressions.map(k =>
        parseKeyExpression({ keyExpression: k, network, isSegwit: true })
      );

      const map: ExpansionMap = {};
      pKEs.forEach((pke, i) => (map['@' + i] = pke));
      expansionMap = map;

      expandedExpression =
        'wsh(sortedmulti(' +
        [m, ...Object.keys(expansionMap).map(k => k)].join(',') +
        '))';

      if (!isCanonicalRanged) {
        const pubkeys = pKEs.map(p => {
          if (!p.pubkey) throw new Error(`Error: key has no pubkey`);
          return p.pubkey;
        });
        pubkeys.sort((a, b) => a.compare(b));

        const redeem = btc.p2ms(m, pubkeys, undefined);
        witnessScript = Buffer.from(redeem.script);

        payment = toPayment(btc.p2wsh(redeem, net) as Record<string, unknown>);
      }
    }
    // sh(wsh(sortedmulti()))
    else if (canonicalExpression.match(RE.reShWshSortedMultiAnchored)) {
      isSegwit = true;
      isTaproot = false;

      const inner = canonicalExpression.match(
        RE.reShWshSortedMultiAnchored
      )?.[1];
      if (!inner)
        throw new Error(`Error extracting sortedmulti() in ${descriptor}`);

      const { m, keyExpressions } = parseSortedMulti(inner);

      const pKEs = keyExpressions.map(k =>
        parseKeyExpression({ keyExpression: k, network, isSegwit: true })
      );

      const map: ExpansionMap = {};
      pKEs.forEach((pke, i) => (map['@' + i] = pke));
      expansionMap = map;

      expandedExpression =
        'sh(wsh(sortedmulti(' +
        [m, ...Object.keys(expansionMap).map(k => k)].join(',') +
        ')))';

      if (!isCanonicalRanged) {
        const pubkeys = pKEs.map(p => {
          if (!p.pubkey) throw new Error(`Error: key has no pubkey`);
          return p.pubkey;
        });
        pubkeys.sort((a, b) => a.compare(b));

        const redeem = btc.p2ms(m, pubkeys, undefined);
        const wsh = btc.p2wsh(redeem, net);

        witnessScript = Buffer.from(redeem.script);
        redeemScript = Buffer.from(wsh.script);

        payment = toPayment(btc.p2sh(wsh, net) as Record<string, unknown>);
      }
    }
    //sh(wsh(miniscript))
    else if (canonicalExpression.match(RE.reShWshMiniscriptAnchored)) {
      isSegwit = true;
      isTaproot = false;
      miniscript = canonicalExpression.match(RE.reShWshMiniscriptAnchored)?.[1];
      if (!miniscript)
        throw new Error(`Error: could not get miniscript in ${descriptor}`);
      ({ expandedMiniscript, expansionMap } = expandMiniscript({
        miniscript,
        isSegwit,
        network
      }));
      expandedExpression = `sh(wsh(${expandedMiniscript}))`;

      if (!isCanonicalRanged) {
        const script = miniscript2Script({ expandedMiniscript, expansionMap });
        witnessScript = script;
        if (script.byteLength > MAX_STANDARD_P2WSH_SCRIPT_SIZE) {
          throw new Error(
            `Error: script is too large, ${script.byteLength} bytes is larger than ${MAX_STANDARD_P2WSH_SCRIPT_SIZE} bytes`
          );
        }
        const nonPushOnlyOps = countNonPushOnlyOPs(script);
        if (nonPushOnlyOps > MAX_OPS_PER_SCRIPT) {
          throw new Error(
            `Error: too many non-push ops, ${nonPushOnlyOps} non-push ops is larger than ${MAX_OPS_PER_SCRIPT}`
          );
        }
        const wshPayment = safeP2wsh(Uint8Array.from(script), net);
        const shPayment = safeP2sh(
          Uint8Array.from(wshPayment.script!),
          net
        );
        payment = shPayment;
        redeemScript = wshPayment.script ?? wshPayment.output;
        if (!redeemScript)
          throw new Error(
            `Error: could not calculate redeemScript for ${descriptor}`
          );
      }
    }
    //sh(miniscript)
    else if (canonicalExpression.match(RE.reShMiniscriptAnchored)) {
      isSegwit = false;
      isTaproot = false;
      miniscript = canonicalExpression.match(RE.reShMiniscriptAnchored)?.[1];
      if (!miniscript)
        throw new Error(`Error: could not get miniscript in ${descriptor}`);
      if (
        allowMiniscriptInP2SH === false &&
        miniscript.search(
          /^(pk\(|pkh\(|wpkh\(|combo\(|multi\(|sortedmulti\(|multi_a\(|sortedmulti_a\()/
        ) !== 0
      ) {
        throw new Error(
          `Error: Miniscript expressions can only be used in wsh`
        );
      }
      ({ expandedMiniscript, expansionMap } = expandMiniscript({
        miniscript,
        isSegwit,
        network
      }));
      expandedExpression = `sh(${expandedMiniscript})`;

      if (!isCanonicalRanged) {
        const script = miniscript2Script({ expandedMiniscript, expansionMap });
        redeemScript = script;
        if (script.byteLength > MAX_SCRIPT_ELEMENT_SIZE) {
          throw new Error(
            `Error: P2SH script is too large, ${script.byteLength} bytes is larger than ${MAX_SCRIPT_ELEMENT_SIZE} bytes`
          );
        }
        const nonPushOnlyOps = countNonPushOnlyOPs(script);
        if (nonPushOnlyOps > MAX_OPS_PER_SCRIPT) {
          throw new Error(
            `Error: too many non-push ops, ${nonPushOnlyOps} non-push ops is larger than ${MAX_OPS_PER_SCRIPT}`
          );
        }
        payment = safeP2sh(Uint8Array.from(script), net);
      }
    }
    //wsh(miniscript)
    else if (canonicalExpression.match(RE.reWshMiniscriptAnchored)) {
      isSegwit = true;
      isTaproot = false;
      miniscript = canonicalExpression.match(RE.reWshMiniscriptAnchored)?.[1];
      if (!miniscript)
        throw new Error(`Error: could not get miniscript in ${descriptor}`);
      ({ expandedMiniscript, expansionMap } = expandMiniscript({
        miniscript,
        isSegwit,
        network
      }));
      expandedExpression = `wsh(${expandedMiniscript})`;

      if (!isCanonicalRanged) {
        const script = miniscript2Script({ expandedMiniscript, expansionMap });
        witnessScript = script;
        if (script.byteLength > MAX_STANDARD_P2WSH_SCRIPT_SIZE) {
          throw new Error(
            `Error: script is too large, ${script.byteLength} bytes is larger than ${MAX_STANDARD_P2WSH_SCRIPT_SIZE} bytes`
          );
        }
        const nonPushOnlyOps = countNonPushOnlyOPs(script);
        if (nonPushOnlyOps > MAX_OPS_PER_SCRIPT) {
          throw new Error(
            `Error: too many non-push ops, ${nonPushOnlyOps} non-push ops is larger than ${MAX_OPS_PER_SCRIPT}`
          );
        }
        payment = safeP2wsh(Uint8Array.from(script), net);
      }
    }
    //tr(KEY) - taproot
    else if (canonicalExpression.match(RE.reTrSingleKeyAnchored)) {
      isSegwit = true;
      isTaproot = true;
      const keyExpression = canonicalExpression.match(RE.reTaprootKeyExp)?.[0];
      if (!keyExpression)
        throw new Error(`Error: keyExpression could not me extracted`);
      if (canonicalExpression !== `tr(${keyExpression})`)
        throw new Error(`Error: invalid expression ${descriptor}`);
      expandedExpression = 'tr(@0)';
      const pKE = parseKeyExpression({
        keyExpression,
        network,
        isSegwit,
        isTaproot
      });
      expansionMap = { '@0': pKE };
      if (!isCanonicalRanged) {
        const pubkey = pKE.pubkey;
        if (!pubkey)
          throw new Error(
            `Error: could not extract a pubkey from ${descriptor}`
          );
        payment = toPayment(btc.p2tr(pubkey, undefined, net) as Record<string, unknown>);
      }
    } else {
      throw new Error(`Error: Could not parse descriptor ${descriptor}`);
    }

    return {
      ...(payment !== undefined ? { payment } : {}),
      ...(expandedExpression !== undefined ? { expandedExpression } : {}),
      ...(miniscript !== undefined ? { miniscript } : {}),
      ...(expansionMap !== undefined ? { expansionMap } : {}),
      ...(isSegwit !== undefined ? { isSegwit } : {}),
      ...(isTaproot !== undefined ? { isTaproot } : {}),
      ...(expandedMiniscript !== undefined ? { expandedMiniscript } : {}),
      ...(redeemScript !== undefined ? { redeemScript } : {}),
      ...(witnessScript !== undefined ? { witnessScript } : {}),
      isRanged,
      canonicalExpression
    };
  }

  /**
   * Expand a miniscript to a generalized form using variables instead of key
   * expressions.
   */
  function expandMiniscript({
    miniscript,
    isSegwit,
    network = networks.bitcoin
  }: {
    miniscript: string;
    isSegwit: boolean;
    network?: Network;
  }): {
    expandedMiniscript: string;
    expansionMap: ExpansionMap;
  } {
    return globalExpandMiniscript({
      miniscript,
      isSegwit,
      isTaproot: false,
      network,
      BIP32,
      ECPair
    });
  }

  /**
   * The `Output` class is the central component for managing descriptors.
   */
  class Output {
    readonly #payment: Payment;
    readonly #preimages: Preimage[] = [];
    readonly #signersPubKeys: Buffer[];
    readonly #miniscript?: string;
    readonly #witnessScript?: Buffer;
    readonly #redeemScript?: Buffer;
    readonly #isSegwit?: boolean;
    readonly #isTaproot?: boolean;
    readonly #expandedExpression?: string;
    readonly #expandedMiniscript?: string;
    readonly #expansionMap?: ExpansionMap;
    readonly #network: Network;

    constructor({
      descriptor,
      index,
      checksumRequired = false,
      allowMiniscriptInP2SH = false,
      network = networks.bitcoin,
      preimages = [],
      signersPubKeys
    }: {
      descriptor: string;
      index?: number;
      checksumRequired?: boolean;
      allowMiniscriptInP2SH?: boolean;
      network?: Network;
      preimages?: Preimage[];
      signersPubKeys?: Buffer[];
    }) {
      this.#network = network;
      this.#preimages = preimages;
      if (typeof descriptor !== 'string')
        throw new Error(`Error: invalid descriptor type`);

      const expandedResult = expand({
        descriptor,
        ...(index !== undefined ? { index } : {}),
        checksumRequired,
        network,
        allowMiniscriptInP2SH
      });
      if (expandedResult.isRanged && index === undefined)
        throw new Error(`Error: index was not provided for ranged descriptor`);
      if (!expandedResult.payment)
        throw new Error(
          `Error: could not extract a payment from ${descriptor}`
        );

      this.#payment = expandedResult.payment;
      if (expandedResult.expandedExpression !== undefined)
        this.#expandedExpression = expandedResult.expandedExpression;
      if (expandedResult.miniscript !== undefined)
        this.#miniscript = expandedResult.miniscript;
      if (expandedResult.expansionMap !== undefined)
        this.#expansionMap = expandedResult.expansionMap;
      if (expandedResult.isSegwit !== undefined)
        this.#isSegwit = expandedResult.isSegwit;
      if (expandedResult.isTaproot !== undefined)
        this.#isTaproot = expandedResult.isTaproot;
      if (expandedResult.expandedMiniscript !== undefined)
        this.#expandedMiniscript = expandedResult.expandedMiniscript;
      if (expandedResult.redeemScript !== undefined)
        this.#redeemScript = expandedResult.redeemScript;
      if (expandedResult.witnessScript !== undefined)
        this.#witnessScript = expandedResult.witnessScript;

      if (signersPubKeys) {
        this.#signersPubKeys = signersPubKeys;
      } else {
        if (this.#expansionMap) {
          this.#signersPubKeys = Object.values(this.#expansionMap).map(
            keyInfo => {
              const pubkey = keyInfo.pubkey;
              if (!pubkey)
                throw new Error(
                  `Error: could not extract a pubkey from ${descriptor}`
                );
              return pubkey;
            }
          );
        } else {
          if (!expandedResult.canonicalExpression.match(RE.reAddrAnchored)) {
            throw new Error(
              `Error: expansionMap not available for expression ${descriptor} that is not an address`
            );
          }
          this.#signersPubKeys = [this.getScriptPubKey()];
        }
      }
      this.getSequence = memoize(this.getSequence);
      this.getLockTime = memoize(this.getLockTime);
      const getSignaturesKey = (
        signatures: PartialSig[] | 'DANGEROUSLY_USE_FAKE_SIGNATURES'
      ) =>
        signatures === 'DANGEROUSLY_USE_FAKE_SIGNATURES'
          ? signatures
          : signatures
              .map(
                s =>
                  `${s.pubkey.toString('hex')}-${s.signature.toString('hex')}`
              )
              .join('|');
      this.getScriptSatisfaction = memoize(
        this.getScriptSatisfaction,
        getSignaturesKey
      );
      this.guessOutput = memoize(this.guessOutput);
      this.inputWeight = memoize(
        this.inputWeight,
        (
          isSegwitTx: boolean,
          signatures: PartialSig[] | 'DANGEROUSLY_USE_FAKE_SIGNATURES'
        ) => {
          const segwitKey = isSegwitTx ? 'segwit' : 'non-segwit';
          const signaturesKey = getSignaturesKey(signatures);
          return `${segwitKey}-${signaturesKey}`;
        }
      );
      this.outputWeight = memoize(this.outputWeight);
    }

    #getTimeConstraints(): TimeConstraints | undefined {
      const miniscript = this.#miniscript;
      const preimages = this.#preimages;
      const expandedMiniscript = this.#expandedMiniscript;
      const expansionMap = this.#expansionMap;
      const signersPubKeys = this.#signersPubKeys;
      if (miniscript) {
        if (expandedMiniscript === undefined || expansionMap === undefined)
          throw new Error(
            `Error: cannot get time constraints from not expanded miniscript ${miniscript}`
          );
        const fakeSignatures = signersPubKeys.map(pubkey => ({
          pubkey,
          signature: Buffer.alloc(72, 0)
        }));
        const { nLockTime, nSequence } = satisfyMiniscript({
          expandedMiniscript,
          expansionMap,
          signatures: fakeSignatures,
          preimages
        });
        return { nLockTime, nSequence };
      } else return undefined;
    }

    getPayment(): Payment {
      return this.#payment;
    }
    getAddress(): string {
      if (!this.#payment.address)
        throw new Error(`Error: could extract an address from the payment`);
      return this.#payment.address;
    }
    getScriptPubKey(): Buffer {
      if (!this.#payment.output)
        throw new Error(`Error: could extract output.script from the payment`);
      return this.#payment.output;
    }
    getScriptSatisfaction(
      signatures: PartialSig[] | 'DANGEROUSLY_USE_FAKE_SIGNATURES'
    ): Buffer {
      if (signatures === 'DANGEROUSLY_USE_FAKE_SIGNATURES')
        signatures = this.#signersPubKeys.map(pubkey => ({
          pubkey,
          signature: Buffer.alloc(72, 0)
        }));
      const miniscript = this.#miniscript;
      const expandedMiniscript = this.#expandedMiniscript;
      const expansionMap = this.#expansionMap;
      if (
        miniscript === undefined ||
        expandedMiniscript === undefined ||
        expansionMap === undefined
      )
        throw new Error(
          `Error: cannot get satisfaction from not expanded miniscript ${miniscript}`
        );
      const scriptSatisfaction = satisfyMiniscript({
        expandedMiniscript,
        expansionMap,
        signatures,
        preimages: this.#preimages,
        timeConstraints: {
          nLockTime: this.getLockTime(),
          nSequence: this.getSequence()
        }
      }).scriptSatisfaction;

      if (!scriptSatisfaction)
        throw new Error(`Error: could not produce a valid satisfaction`);
      return scriptSatisfaction;
    }
    getSequence(): number | undefined {
      return this.#getTimeConstraints()?.nSequence;
    }
    getLockTime(): number | undefined {
      return this.#getTimeConstraints()?.nLockTime;
    }
    getWitnessScript(): Buffer | undefined {
      return this.#witnessScript;
    }
    getRedeemScript(): Buffer | undefined {
      return this.#redeemScript;
    }
    getNetwork(): Network {
      return this.#network;
    }
    isSegwit(): boolean | undefined {
      return this.#isSegwit;
    }
    isTaproot(): boolean | undefined {
      return this.#isTaproot;
    }

    guessOutput() {
      const scriptPubKey = this.getScriptPubKey();
      const decoded = getOutputScriptType(scriptPubKey);
      const scriptType = decoded?.type;
      const isPKH = scriptType === 'pkh';
      const isWPKH = scriptType === 'wpkh';
      const isSH = scriptType === 'sh';
      const isWSH = scriptType === 'wsh';
      const isTR = scriptType === 'tr';

      if ([isPKH, isWPKH, isSH, isWSH, isTR].filter(Boolean).length > 1)
        throw new Error('Cannot have multiple output types.');

      return { isPKH, isWPKH, isSH, isWSH, isTR };
    }

    inputWeight(
      isSegwitTx: boolean,
      signatures: PartialSig[] | 'DANGEROUSLY_USE_FAKE_SIGNATURES'
    ) {
      if (this.isSegwit() && !isSegwitTx)
        throw new Error(`a tx is segwit if at least one input is segwit`);

      const expansion = this.expand().expandedExpression;
      const { isPKH, isWPKH, isSH, isTR } = this.guessOutput();
      const errorMsg = `Input type not implemented. Currently supported: pkh(KEY), wpkh(KEY), tr(KEY), \
sh(wpkh(KEY)), sh(wsh(MINISCRIPT)), sh(MINISCRIPT), wsh(MINISCRIPT), \
addr(PKH_ADDRESS), addr(WPKH_ADDRESS), addr(SH_WPKH_ADDRESS), addr(SINGLE_KEY_ADDRESS). \
expansion=${expansion}, isPKH=${isPKH}, isWPKH=${isWPKH}, isSH=${isSH}, isTR=${isTR}.`;
      if (!expansion && !isPKH && !isWPKH && !isSH && !isTR)
        throw new Error(errorMsg);

      const firstSignature =
        signatures && typeof signatures[0] === 'object'
          ? signatures[0]
          : 'DANGEROUSLY_USE_FAKE_SIGNATURES';

      if (expansion ? expansion.startsWith('pkh(') : isPKH) {
        return (
          (32 + 4 + 4 + 1 + signatureSize(firstSignature) + 34) * 4 +
          (isSegwitTx ? 1 : 0)
        );
      } else if (expansion ? expansion.startsWith('wpkh(') : isWPKH) {
        if (!isSegwitTx) throw new Error('Should be SegwitTx');
        return (
          41 * 4 +
          (1 + signatureSize(firstSignature) + 34)
        );
      } else if (expansion ? expansion.startsWith('sh(wpkh(') : isSH) {
        if (!isSegwitTx) throw new Error('Should be SegwitTx');
        return (
          64 * 4 +
          (1 + signatureSize(firstSignature) + 34)
        );
      } else if (expansion?.startsWith('sh(wsh(')) {
        if (!isSegwitTx) throw new Error('Should be SegwitTx');
        const witnessScript = this.getWitnessScript();
        if (!witnessScript)
          throw new Error('sh(wsh) must provide witnessScript');
        const scriptSatisfaction = this.getScriptSatisfaction(
          signatures || 'DANGEROUSLY_USE_FAKE_SIGNATURES'
        );
        // sh(wsh) input: push of the p2wsh redeemScript (OP_0 <32-byte SHA256(witnessScript)>)
        const redeemScript = this.getRedeemScript();
        if (!redeemScript) throw new Error('sh(wsh) must have redeemScript');
        const shInput = Buffer.concat([
          Buffer.from([redeemScript.length]),
          redeemScript
        ]);
        // witness: satisfaction chunks decompiled from scriptSatisfaction, plus witnessScript
        const witnessChunks = decompileScript(scriptSatisfaction);
        if (!witnessChunks)
          throw new Error('Could not decompile script satisfaction');
        const witness: Buffer[] = witnessChunks.map(chunk =>
          typeof chunk === 'number' ? Buffer.alloc(0) : chunk
        );
        witness.push(witnessScript);
        return (
          4 * (40 + varSliceSize(shInput)) +
          vectorSize(witness)
        );
      } else if (expansion?.startsWith('sh(')) {
        const redeemScript = this.getRedeemScript();
        if (!redeemScript) throw new Error('sh() must provide redeemScript');
        const scriptSatisfaction = this.getScriptSatisfaction(
          signatures || 'DANGEROUSLY_USE_FAKE_SIGNATURES'
        );
        // sh input: scriptSatisfaction + push of redeemScript
        const shInput = Buffer.concat([
          scriptSatisfaction,
          Buffer.from([
            redeemScript.length > 75 ? 0x4c : redeemScript.length
          ]),
          ...(redeemScript.length > 75
            ? [Buffer.from([redeemScript.length])]
            : []),
          redeemScript
        ]);
        return (
          4 * (40 + varSliceSize(shInput)) +
          (isSegwitTx ? 1 : 0)
        );
      } else if (expansion?.startsWith('wsh(')) {
        const witnessScript = this.getWitnessScript();
        if (!witnessScript) throw new Error('wsh must provide witnessScript');
        const scriptSatisfaction = this.getScriptSatisfaction(
          signatures || 'DANGEROUSLY_USE_FAKE_SIGNATURES'
        );
        // wsh: empty scriptSig, witness = satisfaction chunks + witnessScript
        const witnessChunks = decompileScript(scriptSatisfaction);
        if (!witnessChunks)
          throw new Error('Could not decompile script satisfaction');
        const witness: Buffer[] = witnessChunks.map(chunk =>
          typeof chunk === 'number' ? Buffer.alloc(0) : chunk
        );
        witness.push(witnessScript);
        const emptyInput = Buffer.alloc(0);
        return (
          4 * (40 + varSliceSize(emptyInput)) +
          vectorSize(witness)
        );
      } else if (isTR && (!expansion || expansion === 'tr(@0)')) {
        if (!isSegwitTx) throw new Error('Should be SegwitTx');
        return (
          41 * 4 +
          (1 + 65)
        );
      } else {
        throw new Error(errorMsg);
      }
    }

    outputWeight() {
      const { isPKH, isWPKH, isSH, isWSH, isTR } = this.guessOutput();
      const errorMsg = `Output type not implemented. Currently supported: pkh=${isPKH}, wpkh=${isWPKH}, tr=${isTR}, sh=${isSH} and wsh=${isWSH}.`;
      if (isPKH) {
        return 34 * 4;
      } else if (isWPKH) {
        return 31 * 4;
      } else if (isSH) {
        return 32 * 4;
      } else if (isWSH) {
        return 43 * 4;
      } else if (isTR) {
        return 43 * 4;
      } else {
        throw new Error(errorMsg);
      }
    }

    /** @deprecated - Use updatePsbtAsInput instead
     * @hidden
     */
    updatePsbt(params: {
      psbt: PsbtLike;
      txHex?: string;
      txId?: string;
      value?: number;
      vout: number;
      rbf?: boolean;
    }) {
      this.updatePsbtAsInput(params);
      return params.psbt.data.inputs.length - 1;
    }

    updatePsbtAsInput({
      psbt,
      txHex,
      txId,
      value,
      vout,
      rbf = true
    }: {
      psbt: PsbtLike;
      txHex?: string;
      txId?: string;
      value?: number;
      vout: number;
      rbf?: boolean;
    }) {
      if (txHex === undefined) {
        console.warn(`Warning: missing txHex may allow fee attacks`);
      }
      const isSegwit = this.isSegwit();
      if (isSegwit === undefined) {
        throw new Error(
          `Error: could not determine whether this is a segwit descriptor`
        );
      }
      const isTaproot = this.isTaproot();
      if (isTaproot === undefined) {
        throw new Error(
          `Error: could not determine whether this is a taproot descriptor`
        );
      }
      const index = updatePsbt({
        psbt,
        vout,
        ...(txHex !== undefined ? { txHex } : {}),
        ...(txId !== undefined ? { txId } : {}),
        ...(value !== undefined ? { value } : {}),
        ...(isTaproot
          ? { tapInternalKey: this.getPayment().internalPubkey }
          : {}),
        sequence: this.getSequence(),
        locktime: this.getLockTime(),
        keysInfo: this.#expansionMap ? Object.values(this.#expansionMap) : [],
        scriptPubKey: this.getScriptPubKey(),
        isSegwit,
        witnessScript: this.getWitnessScript(),
        redeemScript: this.getRedeemScript(),
        rbf
      });
      const finalizer = ({
        psbt,
        validate = true
      }: {
        psbt: PsbtLike;
        validate?: boolean | undefined;
      }) => this.finalizePsbtInput({ index, psbt, validate });
      return finalizer;
    }

    updatePsbtAsOutput({
      psbt,
      value
    }: {
      psbt: PsbtLike;
      value: number | bigint;
    }) {
      psbt.addOutput({ script: this.getScriptPubKey(), value: typeof value === 'bigint' ? value : BigInt(value) });
    }

    #assertPsbtInput({ psbt, index }: { psbt: PsbtLike; index: number }): void {
      const input = psbt.data.inputs[index];
      const txInput = psbt.txInputs[index];
      if (!input || !txInput)
        throw new Error(`Error: invalid input or txInput`);
      const { sequence: inputSequence, index: vout } = txInput;
      let scriptPubKey: Buffer;
      if (input.witnessUtxo) scriptPubKey = input.witnessUtxo.script;
      else {
        if (!input.nonWitnessUtxo)
          throw new Error(
            `Error: input should have either witnessUtxo or nonWitnessUtxo`
          );
        const tx = btc.Transaction.fromRaw(input.nonWitnessUtxo);
        const out = tx.getOutput(vout);
        if (!out || !out.script) throw new Error(`Error: utxo should exist`);
        scriptPubKey = Buffer.from(out.script);
      }
      const locktime = this.getLockTime() || 0;
      const sequence = this.getSequence();
      const sequenceNoRBF =
        sequence !== undefined
          ? sequence
          : locktime === 0
            ? 0xffffffff
            : 0xfffffffe;
      const sequenceRBF = sequence !== undefined ? sequence : 0xfffffffd;
      const eqBuffers = (buf1: Buffer | undefined, buf2: Buffer | undefined) =>
        buf1 instanceof Buffer && buf2 instanceof Buffer
          ? Buffer.compare(buf1, buf2) === 0
          : buf1 === buf2;
      if (
        Buffer.compare(scriptPubKey, this.getScriptPubKey()) !== 0 ||
        (sequenceRBF !== inputSequence && sequenceNoRBF !== inputSequence) ||
        locktime !== psbt.locktime ||
        !eqBuffers(this.getWitnessScript(), input.witnessScript) ||
        !eqBuffers(this.getRedeemScript(), input.redeemScript)
      ) {
        throw new Error(
          `Error: cannot finalize psbt index ${index} since it does not correspond to this descriptor`
        );
      }
    }

    finalizePsbtInput({
      index,
      psbt,
      validate = true
    }: {
      index: number;
      psbt: PsbtLike;
      validate?: boolean | undefined;
    }): void {
      if (
        validate &&
        !psbt.validateSignaturesOfInput(index, signatureValidator)
      ) {
        throw new Error(`Error: invalid signatures on input ${index}`);
      }

      this.#assertPsbtInput({ index, psbt });
      if (!this.#miniscript) {
        psbt.finalizeInput(index);
      } else {
        const signatures = psbt.data.inputs[index]?.partialSig;
        if (!signatures)
          throw new Error(`Error: cannot finalize without signatures`);
        const scriptSatisfaction = this.getScriptSatisfaction(signatures);
        psbt.finalizeInput(
          index,
          finalScriptsFuncFactory(scriptSatisfaction, this.#network)
        );
      }
    }

    expand() {
      return {
        ...(this.#expandedExpression !== undefined
          ? { expandedExpression: this.#expandedExpression }
          : {}),
        ...(this.#miniscript !== undefined
          ? { miniscript: this.#miniscript }
          : {}),
        ...(this.#expandedMiniscript !== undefined
          ? { expandedMiniscript: this.#expandedMiniscript }
          : {}),
        ...(this.#expansionMap !== undefined
          ? { expansionMap: this.#expansionMap }
          : {})
      };
    }
  }

  /**
   * @hidden
   * @deprecated Use `Output` instead
   */
  class Descriptor extends Output {
    constructor({
      expression,
      ...rest
    }: {
      expression: string;
      index?: number;
      checksumRequired?: boolean;
      allowMiniscriptInP2SH?: boolean;
      network?: Network;
      preimages?: Preimage[];
      signersPubKeys?: Buffer[];
    }) {
      super({ descriptor: expression, ...rest });
    }
  }

  return {
    /** @deprecated @hidden */ Descriptor,
    Output,
    parseKeyExpression,
    expand,
    ECPair,
    BIP32
  };
}

/** @hidden @deprecated */
type DescriptorConstructor = ReturnType<
  typeof DescriptorsFactory
>['Descriptor'];
/** @hidden  @deprecated */
type DescriptorInstance = InstanceType<DescriptorConstructor>;
export { DescriptorInstance, DescriptorConstructor };

type OutputConstructor = ReturnType<typeof DescriptorsFactory>['Output'];
type OutputInstance = InstanceType<OutputConstructor>;
export { OutputInstance, OutputConstructor };
