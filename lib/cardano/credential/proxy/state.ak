//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.

use aiken/cbor
use aiken/crypto
use aiken/primitive/bytearray
use cardano/assets.{AssetName}
use sundae/multisig.{MultisigScript}

pub type DelegateKind {
  BlockProduction
  Governance
}

pub fn match_prefix(kind: DelegateKind, name: AssetName) {
  bytearray.take(name, 4) == prefix(kind)
}

pub fn prefix(kind: DelegateKind) -> ByteArray {
  when kind is {
    BlockProduction -> "blk_"
    Governance -> "gov_"
  }
}

pub fn into_asset_name(kind: DelegateKind, script: MultisigScript) -> AssetName {
  let suffix = crypto.blake2b_224(cbor.serialise(script))
  bytearray.concat(prefix(kind), suffix)
}
