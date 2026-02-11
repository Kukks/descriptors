// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

export type { KeyInfo, Expansion } from './types.js';
export type {
  ECPairAPI,
  ECPairInterface,
  BIP32API,
  BIP32Interface
} from './types.js';
export type { OutputInstance } from './descriptors.js';
export { DescriptorsFactory, OutputConstructor } from './descriptors.js';
export { DescriptorChecksum as checksum } from './checksum.js';

import * as signers from './signers.js';
export { signers };

export { keyExpressionBIP32 } from './keyExpressions.js';
import * as scriptExpressions from './scriptExpressions.js';
export { scriptExpressions };

export type { PsbtLike } from './psbt.js';

export { networks } from './networks.js';
export type { Network } from './networks.js';

// Built-in adapters using @noble/curves and @scure/bip32
export { nobleECPair, scureBIP32 } from './adapters.js';

// Pre-built factory using built-in adapters (zero-config convenience)
import { DescriptorsFactory } from './descriptors.js';
export const defaultFactory = DescriptorsFactory();
