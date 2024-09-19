use crate::{cardano::Cardano, contract::*, pallas_extra::*};

use pallas_codec::utils::{Bytes, NonZeroInt, Nullable, PositiveCoin, Set};
use pallas_crypto::hash::Hash;
use pallas_primitives::conway::{
    Certificate, Language, PlutusV3Script, PostAlonzoTransactionOutput, PseudoTransactionOutput,
    RedeemerTag, RedeemersKey, RedeemersValue, StakeCredential, TransactionBody, Tx, Value,
    WitnessSet,
};
use uplc::tx::ResolvedInput;

pub(crate) async fn delegate(
    network: Cardano,
    validator: Bytes,
    administrators: Vec<Hash<28>>,
    delegates: Vec<Hash<28>>,
    quorum: usize,
    OutputReference(fuel): OutputReference,
) -> Tx {
    let (validator_hash, validator_address) =
        from_validator(validator.as_ref(), network.network_id());

    let params = network.protocol_parameters().await;

    let fuel_output = network
        .resolve(&fuel)
        .await
        .expect("failed to resolve fuel UTxO");

    let resolved_inputs = &[ResolvedInput {
        input: fuel.clone(),
        output: PseudoTransactionOutput::PostAlonzo(fuel_output.clone()),
    }];

    let build_params = (
        params.fee_coefficient,
        params.fee_constant,
        (params.price_mem, params.price_steps),
    );

    build_transaction(build_params, resolved_inputs, |fee, ex_units| {
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
                value: subtract(fuel_output.value.clone(), total_cost).expect("not enough fuel"),
                datum_option: None,
                script_ref: None,
            },
        ];

        let collateral_return = PostAlonzoTransactionOutput {
            address: fuel_output.address.clone(),
            value: subtract(fuel_output.value.clone(), total_collateral).expect("not enough fuel"),
            datum_option: None,
            script_ref: None,
        };

        let mint = singleton_assets(
            validator_hash,
            &[(asset_name, NonZeroInt::try_from(1).unwrap())],
        );
        redeemers.push((
            RedeemersKey {
                tag: RedeemerTag::Mint,
                index: 0,
            },
            RedeemersValue {
                data: void(),
                ex_units: ex_units[0],
            },
        ));

        let certificates = vec![Certificate::RegDRepCert(
            StakeCredential::Scripthash(validator_hash),
            params.drep_deposit,
            Nullable::Null,
        )];
        redeemers.push((
            RedeemersKey {
                tag: RedeemerTag::Cert,
                index: 0,
            },
            RedeemersValue {
                data: rules,
                ex_units: ex_units[1],
            },
        ));

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
    })
}

pub(crate) async fn redelegate(
    network: Cardano,
    administrators: Vec<Hash<28>>,
    delegates: Vec<Hash<28>>,
    quorum: usize,
    OutputReference(contract): OutputReference,
    OutputReference(fuel): OutputReference,
) -> Tx {
    let (validator, validator_hash, validator_address) =
        recover_validator(&network, &contract.transaction_id).await;

    let params = network.protocol_parameters().await;

    let contract_old_output = network
        .resolve(&contract)
        .await
        .expect("failed to resolve contract UTxO");

    let fuel_output = network
        .resolve(&fuel)
        .await
        .expect("failed to resolve fuel UTxO");

    let resolved_inputs = &[
        ResolvedInput {
            input: contract.clone(),
            output: PseudoTransactionOutput::PostAlonzo(contract_old_output.clone()),
        },
        ResolvedInput {
            input: fuel.clone(),
            output: PseudoTransactionOutput::PostAlonzo(fuel_output.clone()),
        },
    ];

    let build_params = (
        params.fee_coefficient,
        params.fee_constant,
        (params.price_mem, params.price_steps),
    );

    build_transaction(build_params, resolved_inputs, |fee, ex_units| {
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

        let total_cost =
            lovelace_of(&contract_new_output.value) + fee - lovelace_of(&contract_old_output.value);

        let mint = singleton_assets(
            validator_hash,
            &[
                (new_asset_name, NonZeroInt::try_from(1).unwrap()),
                (old_asset_name, NonZeroInt::try_from(-1).unwrap()),
            ],
        );
        redeemers.push((
            RedeemersKey {
                tag: RedeemerTag::Mint,
                index: 0,
            },
            RedeemersValue {
                data: void(),
                ex_units: ex_units[0],
            },
        ));

        let outputs = vec![
            // Contract
            contract_new_output,
            // Change
            PostAlonzoTransactionOutput {
                address: fuel_output.address.clone(),
                value: subtract(fuel_output.value.clone(), total_cost).expect("not enough fuel"),
                datum_option: None,
                script_ref: None,
            },
        ];

        let collateral_return = PostAlonzoTransactionOutput {
            address: fuel_output.address.clone(),
            value: subtract(fuel_output.value.clone(), total_collateral).expect("not enough fuel"),
            datum_option: None,
            script_ref: None,
        };

        redeemers.push((
            RedeemersKey {
                tag: RedeemerTag::Spend,
                index: inputs
                    .iter()
                    .enumerate()
                    .find(|(_, i)| *i == &contract)
                    .unwrap()
                    .0 as u32,
            },
            RedeemersValue {
                data: void(),
                ex_units: ex_units[1],
            },
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
        redeemers.push((
            RedeemersKey {
                tag: RedeemerTag::Cert,
                index: 0,
            },
            RedeemersValue {
                data: void(),
                ex_units: ex_units[2],
            },
        ));
        redeemers.push((
            RedeemersKey {
                tag: RedeemerTag::Cert,
                index: 1,
            },
            RedeemersValue {
                data: rules,
                ex_units: ex_units[3],
            },
        ));

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
    })
}
