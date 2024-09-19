//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crate::{cardano::Cardano, contract::*, pallas_extra::*};
use clap::{ArgGroup, Command};
use indoc::indoc;
use pallas_codec::utils::{Bytes, NonZeroInt, Nullable, PositiveCoin, Set};
use pallas_crypto::hash::Hash;
use pallas_primitives::conway::{
    Certificate, Language, PlutusV3Script, PostAlonzoTransactionOutput, PseudoTransactionOutput,
    StakeCredential, TransactionBody, Tx, Value, WitnessSet,
};

pub(crate) fn cmd() -> Command {
    Command::new("delegate")
        .about(indoc! {
            r#"Hand-over voting rights to a group of delegates (hot credentials)."#
        })
        .after_help(color_print::cstr!(
                    r#"<underline><bold>Notes:</bold></underline>
  1. The <bold>--contract</bold> option is only mandatory for re-delegation (as it typically doesn't exist otherwise).
  2. The specified <bold>--administrator</bold> must reflect the signatories for the transaction, but not necessarily ALL administrators.
     Only those authorizing the transaction must be present. And, there must be enough signatories for a quorum.

<underline><bold>Examples:</bold></underline>
<italic>1. No previous contract instance, defining a 1-of-2 hot delegate: </italic>
  <bold>delegate</bold> \
    <bold>--quorum</bold> 1 \
    <bold>--delegate</bold> 000000000000000000000000000000000000000000000000000a11ce \
    <bold>--delegate</bold> 00000000000000000000000000000000000000000000000000000b0b \
    <bold>--validator</bold> $(jq -r ".validators[0].compiledCode" plutus.json) \
    <bold>--administrator</bold> 0000000000000000000000000000000000000000000000000000090d \
    <bold>--fuel</bold> "ab5334d2db6f7909b511ee9c0f7181c7f4da515ba15f186d95caef0d91ac4a11#0"

<italic>2. Re-delegation, defining now a 2-of-3 hot delegate: </italic>
  <bold>delegate</bold> \
    <bold>--quorum</bold> 2 \
    <bold>--delegate</bold> 000000000000000000000000000000000000000000000000000a11ce \
    <bold>--delegate</bold> 00000000000000000000000000000000000000000000000000000b0b \
    <bold>--delegate</bold> 000000000000000000000000000000000000000000000000000ca201 \
    <bold>--contract</bold> "8d5726c0e7cb207a3f5881d29a7ceba71f578c2165a2261340c242bdba6875dd#0" \
    <bold>--administrator</bold> 0000000000000000000000000000000000000000000000000000090d \
    <bold>--fuel</bold> "ab5334d2db6f7909b511ee9c0f7181c7f4da515ba15f186d95caef0d91ac4a11#0"
"#              ))
    .arg(super::arg_delegate())
    .arg(super::arg_quorum())
    .arg(super::arg_validator())
    .arg(super::arg_contract(false))
    .arg(super::arg_administrator())
    .arg(super::arg_fuel())
    .group(ArgGroup::new("source")
        .args(["contract", "validator"])
        .multiple(false)
        .required(true)
    )
}

pub(crate) async fn delegate(
    network: Cardano,
    delegates: Vec<Hash<28>>,
    quorum: usize,
    administrators: Vec<Hash<28>>,
    validator: Bytes,
    OutputReference(fuel): OutputReference,
) -> Tx {
    let (validator_hash, validator_address) =
        from_validator(validator.as_ref(), network.network_id());

    let params = network.protocol_parameters().await;

    let resolved_inputs = network.resolve_many(&[&fuel]).await;
    let fuel_output = expect_post_alonzo(&resolved_inputs[0].output);

    build_transaction(
        &BuildParams::from(&params),
        &resolved_inputs[..],
        |fee, ex_units| {
            let (rules, asset_name) = build_rules(&delegates[..], quorum);

            let contract_output =
                new_min_value_output(params.min_utxo_deposit_coefficient, |lovelace| {
                    PostAlonzoTransactionOutput {
                        address: validator_address.to_vec().into(),
                        value: Value::Multiasset(
                            lovelace,
                            singleton_assets(
                                validator_hash,
                                &[(asset_name.clone(), PositiveCoin::try_from(1).unwrap())],
                            ),
                        ),
                        datum_option: None,
                        script_ref: None,
                    }
                });

            let total_collateral = (fee as f64 * params.collateral_percent).ceil() as u64;

            let mut redeemers = vec![];

            let inputs = vec![fuel.clone()];

            let total_cost = params.drep_deposit + lovelace_of(&contract_output.value) + fee;

            let outputs = vec![
                // Contract
                contract_output,
                // Change
                PostAlonzoTransactionOutput {
                    address: fuel_output.address.clone(),
                    value: value_subtract_lovelace(fuel_output.value.clone(), total_cost)
                        .expect("not enough fuel"),
                    datum_option: None,
                    script_ref: None,
                },
            ];

            let collateral_return = PostAlonzoTransactionOutput {
                address: fuel_output.address.clone(),
                value: value_subtract_lovelace(fuel_output.value.clone(), total_collateral)
                    .expect("not enough fuel"),
                datum_option: None,
                script_ref: None,
            };

            let mint = singleton_assets(
                validator_hash,
                &[(asset_name, NonZeroInt::try_from(1).unwrap())],
            );
            redeemers.push(Redeemer::mint(0, void(), ex_units[0]));

            let certificates = vec![Certificate::RegDRepCert(
                StakeCredential::Scripthash(validator_hash),
                params.drep_deposit,
                Nullable::Null,
            )];
            redeemers.push(Redeemer::publish(0, rules, ex_units[1]));

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

pub(crate) async fn redelegate(
    network: Cardano,
    delegates: Vec<Hash<28>>,
    quorum: usize,
    administrators: Vec<Hash<28>>,
    OutputReference(contract): OutputReference,
    OutputReference(fuel): OutputReference,
) -> Tx {
    let (validator, validator_hash, validator_address) =
        recover_validator(&network, &contract.transaction_id).await;

    let params = network.protocol_parameters().await;

    let resolved_inputs = network.resolve_many(&[&fuel, &contract]).await;
    let fuel_output = expect_post_alonzo(&resolved_inputs[0].output);
    let contract_old_output = expect_post_alonzo(&resolved_inputs[1].output);

    build_transaction(
        &BuildParams::from(&params),
        &resolved_inputs[..],
        |fee, ex_units| {
            let (rules, new_asset_name) = build_rules(&delegates[..], quorum);

            let old_asset_name = find_contract_token(&contract_old_output.value)
                .expect("no state token in contract utxo?");

            let contract_new_output =
                new_min_value_output(params.min_utxo_deposit_coefficient, |lovelace| {
                    PostAlonzoTransactionOutput {
                        address: validator_address.to_vec().into(),
                        value: Value::Multiasset(
                            lovelace,
                            singleton_assets(
                                validator_hash,
                                &[(new_asset_name.clone(), PositiveCoin::try_from(1).unwrap())],
                            ),
                        ),
                        datum_option: None,
                        script_ref: None,
                    }
                });

            let total_collateral = (fee as f64 * params.collateral_percent).ceil() as u64;

            let mut redeemers = vec![];

            let mut inputs = vec![contract.clone(), fuel.clone()];
            inputs.sort();

            let total_cost = lovelace_of(&contract_new_output.value) + fee
                - lovelace_of(&contract_old_output.value);

            let mint = singleton_assets(
                validator_hash,
                &[
                    (new_asset_name, NonZeroInt::try_from(1).unwrap()),
                    (old_asset_name, NonZeroInt::try_from(-1).unwrap()),
                ],
            );
            redeemers.push(Redeemer::mint(0, void(), ex_units[0]));

            let outputs = vec![
                // Contract
                contract_new_output,
                // Change
                PostAlonzoTransactionOutput {
                    address: fuel_output.address.clone(),
                    value: value_subtract_lovelace(fuel_output.value.clone(), total_cost)
                        .expect("not enough fuel"),
                    datum_option: None,
                    script_ref: None,
                },
            ];

            let collateral_return = PostAlonzoTransactionOutput {
                address: fuel_output.address.clone(),
                value: value_subtract_lovelace(fuel_output.value.clone(), total_collateral)
                    .expect("not enough fuel"),
                datum_option: None,
                script_ref: None,
            };

            redeemers.push(Redeemer::spend(
                (&inputs[..], &contract),
                void(),
                ex_units[1],
            ));

            let certificates = vec![
                Certificate::UnRegDRepCert(
                    StakeCredential::Scripthash(validator_hash),
                    params.drep_deposit,
                ),
                Certificate::RegDRepCert(
                    StakeCredential::Scripthash(validator_hash),
                    params.drep_deposit,
                    Nullable::Null,
                ),
            ];
            redeemers.push(Redeemer::publish(0, void(), ex_units[2]));
            redeemers.push(Redeemer::publish(1, rules, ex_units[3]));

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
