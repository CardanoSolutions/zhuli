//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.

use aiken/crypto.{ScriptHash}
use aiken/fuzz.{both}
use cardano/address.{Address}
use cardano/assets.{ada_policy_id}
use cardano/generator.{any_ada_only_value, any_value_with}
use sundae/multisig.{MultisigScript}
use zhuli/predicate.{must_forward_strict_assets}

// NOTE: Needs not to be an actual policy id, as we never re-hash anything. So
// we might as well make it something we can easily recognize.
pub const validator_hash: ScriptHash = "direct-proxy"

pub const validator_address: Address =
  address.from_script(validator_hash)
    |> address.with_delegation_script(validator_hash)

// NOTE: Similarly, we need not the administrator script to be anything complex,
// nor to be a valid key hash.
pub const administrator: MultisigScript = multisig.Signature("administrator")

// -----------------------------------------------------------------------------
// ------------------------------------------------ must_forward_strict_assets -
// -----------------------------------------------------------------------------

test prop_forward_assets_only_lovelace(
  (from, to) via both(any_ada_only_value(), any_ada_only_value()),
) {
  must_forward_strict_assets(validator_hash, from, to)
}

test prop_forward_assets_is_restricted(from via any_value_with(validator_hash)) {
  let to = assets.restricted_to(from, [ada_policy_id, validator_hash])
  must_forward_strict_assets(validator_hash, from, to)
}

test prop_forward_assets_extranenous(
  from via any_value_with(validator_hash),
) fail once {
  must_forward_strict_assets(validator_hash, from, from)
}
