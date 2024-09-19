//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crate::{cardano::Cardano, contract::*, pallas_extra::*};
use clap::Command;
use pallas_codec::utils::{NonZeroInt, Nullable, Set};
use pallas_crypto::hash::Hash;
use pallas_primitives::conway::{
    Certificate, Language, PlutusV3Script, PostAlonzoTransactionOutput, PseudoTransactionOutput,
    StakeCredential, TransactionBody, Tx, WitnessSet,
};

pub(crate) fn cmd() -> Command {
    Command::new("revoke")
        .about("Revoke delegation, without defining a new delegate.")
        .after_help(color_print::cstr!(
            r#"<underline><bold>Notes:</bold></underline>
  1. This operation effectively <underline>unregisters the delegate representative</underline>!
  2. The specified <bold>--administrator</bold> must reflect the signatories for the transaction, but not necessarily ALL administrators.
     Only those authorizing the transaction must be present. And, there must be enough signatories for a quorum.

<underline><bold>Examples:</bold></underline>
  <bold>revoke</bold> \
    <bold>--contract</bold> "8d5726c0e7cb207a3f5881d29a7ceba71f578c2165a2261340c242bdba6875dd#0" \
    <bold>--administrator</bold> 0000000000000000000000000000000000000000000000000000090d \
    <bold>--fuel</bold> "ab5334d2db6f7909b511ee9c0f7181c7f4da515ba15f186d95caef0d91ac4a11#0"
"#              ))
        .arg(super::arg_administrator())
        .arg(super::arg_contract(true))
        .arg(super::arg_fuel())
}

pub(crate) async fn revoke(
    network: Cardano,
    administrators: Vec<Hash<28>>,
    OutputReference(contract): OutputReference,
    OutputReference(fuel): OutputReference,
) -> Tx {
    let (validator, validator_hash, _) =
        recover_validator(&network, &contract.transaction_id).await;

    let params = network.protocol_parameters().await;

    let resolved_inputs = network.resolve_many(&[&fuel, &contract]).await;
    let fuel_output = expect_post_alonzo(&resolved_inputs[0].output);
    let contract_output = expect_post_alonzo(&resolved_inputs[1].output);

    let asset_name =
        find_contract_token(&contract_output.value).expect("no state token in contract utxo?");

    build_transaction(
        &BuildParams::from(&params),
        &resolved_inputs[..],
        |fee, ex_units| {
            let mut redeemers = vec![];

            let mint = singleton_assets(
                validator_hash,
                &[(asset_name.clone(), NonZeroInt::try_from(-1).unwrap())],
            );
            redeemers.push(Redeemer::mint(0, void(), ex_units[0]));

            let mut inputs = vec![contract.clone(), fuel.clone()];
            inputs.sort();
            redeemers.push(Redeemer::spend(
                (&inputs[..], &contract),
                void(),
                ex_units[1],
            ));

            let outputs = vec![
                // Change
                PostAlonzoTransactionOutput {
                    address: fuel_output.address.clone(),
                    value: value_subtract_lovelace(
                        value_add_lovelace(
                            fuel_output.value.clone(),
                            params.drep_deposit + lovelace_of(&contract_output.value),
                        ),
                        fee,
                    )
                    .expect("not enough fuel"),
                    datum_option: None,
                    script_ref: None,
                },
            ];

            let total_collateral = (fee as f64 * params.collateral_percent).ceil() as u64;

            let collateral_return = PostAlonzoTransactionOutput {
                address: fuel_output.address.clone(),
                value: value_subtract_lovelace(fuel_output.value.clone(), total_collateral)
                    .expect("not enough fuel"),
                datum_option: None,
                script_ref: None,
            };

            let certificates = vec![Certificate::UnRegDRepCert(
                StakeCredential::Scripthash(validator_hash),
                params.drep_deposit,
            )];
            redeemers.push(Redeemer::publish(0, void(), ex_units[2]));

            // ----- Put it all together
            let redeemers = non_empty_pairs(redeemers).unwrap();
            Tx {
                transaction_body: TransactionBody {
                    inputs: Set::from(inputs),
                    network_id: Some(from_network(network.network_id())),
                    outputs: into_outputs(outputs),
                    mint: Some(mint),
                    certificates: non_empty_set(certificates),
                    fee,
                    collateral: non_empty_set(vec![fuel.clone()]),
                    collateral_return: Some(PseudoTransactionOutput::PostAlonzo(collateral_return)),
                    total_collateral: Some(total_collateral),
                    required_signers: non_empty_set(administrators.clone()),
                    script_data_hash: Some(
                        script_integrity_hash(
                            Some(&redeemers),
                            None,
                            &[(Language::PlutusV3, &params.cost_model_v3[..])],
                        )
                        .unwrap(),
                    ),
                    ..default_transaction_body()
                },
                transaction_witness_set: WitnessSet {
                    redeemer: Some(redeemers.into()),
                    plutus_v3_script: non_empty_set(vec![PlutusV3Script(validator.clone())]),
                    ..default_witness_set()
                },
                success: true,
                auxiliary_data: Nullable::Null,
            }
        },
    )
}
