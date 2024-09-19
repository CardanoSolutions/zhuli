//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crate::{cardano::Cardano, pallas_extra::*};
use pallas_addresses::ShelleyAddress;
use pallas_codec::utils::Bytes;
use pallas_crypto::hash::{Hash, Hasher};
use pallas_primitives::conway::{AssetName, Constr, PlutusData, RedeemerTag, Value};

pub(crate) fn build_rules(delegates: &[Hash<28>], quorum: usize) -> (PlutusData, AssetName) {
    assert!(
        quorum <= delegates.len(),
        "quorum cannot be larger than number of delegates"
    );

    assert!(!delegates.is_empty(), "there must be at least one delegate");

    let rules = PlutusData::Constr(Constr {
        tag: 123,
        any_constructor: None,
        fields: vec![PlutusData::Array(
            delegates
                .iter()
                .map(|delegate| {
                    PlutusData::Constr(Constr {
                        tag: 121,
                        any_constructor: None,
                        fields: vec![PlutusData::BoundedBytes(
                            delegate.as_slice().to_vec().into(),
                        )],
                    })
                })
                .collect::<Vec<_>>(),
        )],
    });

    let mut asset_name = "gov_".as_bytes().to_vec();
    asset_name.extend(Hasher::<224>::hash_cbor(&rules).as_slice());

    (rules, asset_name.into())
}

// To avoid re-asking users for the delegates and quorum during vote (which is (1) inconvenient,
// and (2), utterly confusing with the existing delegates signatories...), we pull the rules from
// the minting transaction corresponding to the current state token. The token is always minted
// alongside a DRep registration certificate which defines the new rules as redeemer.
pub(crate) async fn recover_rules(
    network: &Cardano,
    validator_hash: &Hash<28>,
    contract_value: &Value,
) -> (PlutusData, AssetName) {
    let asset_name = find_contract_token(contract_value).expect("no state token in contract utxo?");

    let minting_txs = network.minting(validator_hash, &asset_name).await;

    let minting_tx = minting_txs.first().unwrap_or_else(|| {
        panic!(
            "no minting transaction found for {}",
            hex::encode(&asset_name[..]),
        )
    });

    let rules = if let Some(ref redeemers) = minting_tx.transaction_witness_set.redeemer {
        redeemers
            .iter()
            .find_map(|(key, value)| {
                if key.tag == RedeemerTag::Cert && value.data != void() {
                    Some(value.data.clone())
                } else {
                    None
                }
            })
            .expect("could not find registration certificate alongside minting transaction?!")
    } else {
        unreachable!()
    };

    (rules, asset_name)
}

pub(crate) async fn recover_validator(
    network: &Cardano,
    transaction_id: &Hash<32>,
) -> (Bytes, Hash<28>, ShelleyAddress) {
    let validator = network
        .transaction_by_hash(&hex::encode(transaction_id))
        .await
        .expect("Could not resolve contract UTxO?")
        .transaction_witness_set
        .plutus_v3_script
        .expect("No Plutus script found in the provided contract UTxO?")
        .first()
        .unwrap()
        .to_owned()
        .0;

    let (validator_hash, validator_address) =
        from_validator(validator.as_ref(), network.network_id());

    (validator, validator_hash, validator_address)
}

pub(crate) fn find_contract_token(value: &Value) -> Option<AssetName> {
    match value {
        Value::Multiasset(_, ref assets) => assets
            .first()
            .and_then(|(_, assets)| assets.first().cloned()),
        _ => None,
    }
    .map(|pair| pair.0)
}
