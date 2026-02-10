// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

export type { KeyInfo, Expansion } from './types.js';
export type { OutputInstance } from './descriptors.js';
export {
  DescriptorsFactory,
  OutputConstructor
} from './descriptors.js';
export { DescriptorChecksum as checksum } from './checksum.js';

import * as signers from './signers.js';
export { signers };

export { keyExpressionBIP32 } from './keyExpressions.js';
import * as scriptExpressions from './scriptExpressions.js';
export { scriptExpressions };

export type { PsbtLike } from './psbt.js';
