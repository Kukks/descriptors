// Test that @bitcoinerlab/miniscript is an optional dependency.
// Non-miniscript descriptors must work regardless; miniscript descriptors
// require the peer dependency to be installed.

import { DescriptorsFactory, ensureMiniscriptLoaded } from '../dist/index.js';

const { Output } = DescriptorsFactory();

describe('Optional @bitcoinerlab/miniscript dependency', () => {
  test('non-miniscript descriptors work without miniscript lib', () => {
    // wpkh — should never touch miniscript code path
    const wpkh = new Output({
      descriptor:
        'wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)'
    });
    expect(wpkh.getAddress()).toBeDefined();

    // pkh
    const pkh = new Output({
      descriptor:
        'pkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)'
    });
    expect(pkh.getAddress()).toBeDefined();

    // tr (taproot single key)
    const tr = new Output({
      descriptor:
        'tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)'
    });
    expect(tr.getAddress()).toBeDefined();
  });

  test('ensureMiniscriptLoaded resolves when lib is installed', async () => {
    // The lib IS installed as a devDependency, so this should resolve.
    await expect(ensureMiniscriptLoaded()).resolves.toBeUndefined();
  });

  test('miniscript descriptors work after lib is loaded', async () => {
    await ensureMiniscriptLoaded();
    // wsh(miniscript) descriptor — exercises the miniscript code path
    const output = new Output({
      descriptor:
        'wsh(and_v(v:pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5),pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)))'
    });
    expect(output.getAddress()).toBeDefined();
  });
});
