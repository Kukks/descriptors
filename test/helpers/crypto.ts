// Re-export built-in adapters from the library source.
// Tests use these to construct DescriptorsFactory instances.
export {
  nobleECPair as ECPair,
  scureBIP32 as BIP32
} from '../../src/adapters.js';
export { networks } from '../../src/networks.js';
