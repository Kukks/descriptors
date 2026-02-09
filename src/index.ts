// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

export type { KeyInfo, Expansion } from './types';
import type { PsbtLike } from './psbt';
import type { OutputInstance } from './descriptors';
export type { DescriptorInstance, OutputInstance } from './descriptors';
export {
  DescriptorsFactory,
  DescriptorConstructor,
  OutputConstructor
} from './descriptors';
export { DescriptorChecksum as checksum } from './checksum';

import * as signers from './signers';
export { signers };

/**
 * @hidden @deprecated
 * To finalize the `psbt`, you can either call the method
 * `output.finalizePsbtInput({ index, psbt })` on each descriptor, passing as
 * arguments the `psbt` and its input `index`, or call this helper function:
 * `finalizePsbt({psbt, outputs })`. In the latter case, `outputs` is an
 * array of {@link _Internal_.Output | Output elements} ordered in the array by
 * their respective input index in the `psbt`.
 */
function finalizePsbt({
  psbt,
  outputs,
  descriptors,
  validate = true
}: {
  psbt: PsbtLike;
  outputs?: OutputInstance[];
  /** @deprecated use outputs */
  descriptors?: OutputInstance[];
  validate?: boolean | undefined;
}) {
  if (descriptors && outputs)
    throw new Error(`descriptors param has been deprecated`);
  outputs = descriptors || outputs;
  if (!outputs) throw new Error(`outputs not provided`);
  outputs.forEach((output, inputIndex) =>
    output.finalizePsbtInput({ index: inputIndex, psbt, validate })
  );
}

export { finalizePsbt };

export { keyExpressionBIP32 } from './keyExpressions';
import * as scriptExpressions from './scriptExpressions';
export { scriptExpressions };

export type { PsbtLike } from './psbt';
