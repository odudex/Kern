# libwally-core

`upstream` is a submodule pinned to a commit of the fork at github.com/odudex/libwally-core, on a `tapscript-pr-vN` branch. `kern_wally.c` holds Kern's allocation adapters (see `kern_wally.h`).

## Bumping the pin

1. Before re-pointing, tag the commit currently pinned (`git push <fork> <sha>:refs/tags/kern-pin-<sha12>`), and tag the old head of any pinned `tapscript-pr-vN` branch before force-pushing it: a release whose pin no ref reaches cannot be rebuilt once GitHub collects it.
2. Check the new pin still carries the fork behaviours Kern relies on. The host tests pin them (`just test`), but read the log too. The fork branch gets rebased, so find these commits by subject: `descriptor: reject non-sane scripts by default` (non-sane miniscript rejected), `psbt: don't require a witness utxo to sign segwit inputs` (BIP143 signing of a segwit input carrying only a non_witness_utxo), `descriptor: reject un-derivable keys at parse time` (no hardened step after a multipath tuple), `psbt: update the v2 modifiable flags when signing` (BIP-370 flags cleared by the signer) and `descriptor: update key uniqueness checks to derive keys` (a repeated key rejected however it is written).
3. Run the fork's own PSBT tests, `src/test/test_psbt.py`, which `just test` does not.
4. `just test`, `just test-asan`, `just build <board>` for every board and `just sim-build`, then the device checks of the change.
5. Tag the new pin like step 1.
