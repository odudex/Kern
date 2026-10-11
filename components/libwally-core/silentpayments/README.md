# secp256k1 silentpayments module

`include/secp256k1_silentpayments.h` and `src/modules/silentpayments/main_impl.h` are copied
unchanged from [bitcoin-core/secp256k1#1765](https://github.com/bitcoin-core/secp256k1/pull/1765)
at commit `cea6d114109aff49ce26a9d4e2f8c1106e36f2bc`. The tree layout mirrors secp256k1 so the
module's relative includes resolve against libwally's bundled secp256k1-zkp, and
`../kern_combined.c` compiles it in the same translation unit.
