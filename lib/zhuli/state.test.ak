////  This Source Code Form is subject to the terms of the Mozilla Public
////  License, v. 2.0. If a copy of the MPL was not distributed with this
////  file, You can obtain one at http://mozilla.org/MPL/2.0/.

use aiken/collection/list
use aiken/fuzz.{
  and_then, both, bytearray_between, constant, either, int, int_between,
  label_when, list_between, map,
}
use sundae/multisig.{
  After, AllOf, AnyOf, AtLeast, Before, MultisigScript, Script, Signature,
}
use zhuli/state.{
  BlockProduction, DelegateKind, Governance, into_asset_name, match_prefix,
}

test prop_prefix(
  (kind, script) via both(any_delegate_kind(), any_multisig_script()),
) {
  label_when(kind == Governance, @"Governance", @"BlockProduction")
  match_prefix(kind, into_asset_name(kind, script))
}

fn any_delegate_kind() -> Fuzzer<DelegateKind> {
  either(constant(BlockProduction), constant(Governance))
}

fn any_multisig_script() -> Fuzzer<MultisigScript> {
  any_multisig_script_at_depth(3)
}

fn any_multisig_script_at_depth(depth: Int) -> Fuzzer<MultisigScript> {
  if depth <= 0 {
    map(bytearray_between(28, 28), Signature)
  } else {
    let variant <- and_then(int_between(0, 7))
    if variant < 4 {
      if variant < 2 {
        if variant < 1 {
          map(bytearray_between(28, 28), Signature)
        } else {
          map(
            list_between(any_multisig_script_at_depth(depth - 1), 0, depth),
            AllOf,
          )
        }
      } else {
        if variant == 2 {
          map(
            list_between(any_multisig_script_at_depth(depth - 1), 0, depth),
            AnyOf,
          )
        } else {
          let scripts <-
            and_then(
              list_between(any_multisig_script_at_depth(depth - 1), 0, depth),
            )
          let required <- map(int_between(0, list.length(scripts)))
          AtLeast { required, scripts }
        }
      }
    } else {
      if variant < 6 {
        if variant < 5 {
          map(int(), Before)
        } else {
          map(int(), After)
        }
      } else {
        map(bytearray_between(28, 28), Script)
      }
    }
  }
}
