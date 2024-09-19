use crate::{cardano::Cardano, contract::*, pallas_extra::*};
use pallas_codec::utils::{NonEmptyKeyValuePairs, Nullable, Set};
use pallas_crypto::hash::Hash;
use pallas_primitives::conway::{
    Anchor, GovActionId, Language, PlutusV3Script, PostAlonzoTransactionOutput,
    PseudoTransactionOutput, RedeemerTag, RedeemersKey, RedeemersValue, TransactionBody, Tx, Vote,
    Voter, VotingProcedure, WitnessSet,
};
use uplc::tx::ResolvedInput;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn vote(
    network: Cardano,
    delegates: Vec<Hash<28>>,
    choice: Vote,
    anchor: Option<Anchor>,
    proposal_id: GovActionId,
    OutputReference(contract): OutputReference,
    OutputReference(fuel): OutputReference,
) -> Tx {
    let (validator, validator_hash, _) =
        recover_validator(&network, &contract.transaction_id).await;

    let params = network.protocol_parameters().await;

    let contract_output = network
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
            output: PseudoTransactionOutput::PostAlonzo(contract_output.clone()),
        },
        ResolvedInput {
            input: fuel.clone(),
            output: PseudoTransactionOutput::PostAlonzo(fuel_output.clone()),
        },
    ];

    let (rules, _) = recover_rules(&network, &validator_hash, &contract_output.value).await;

    let build_params = (
        params.fee_coefficient,
        params.fee_constant,
        (params.price_mem, params.price_steps),
    );

    build_transaction(build_params, resolved_inputs, |fee, ex_units| {
        let mut redeemers = vec![];

        let inputs = vec![fuel.clone()];

        let reference_inputs = vec![contract.clone()];

        let outputs = vec![
            // Change
            PostAlonzoTransactionOutput {
                address: fuel_output.address.clone(),
                value: subtract(fuel_output.value.clone(), fee).expect("not enough fuel"),
                datum_option: None,
                script_ref: None,
            },
        ];

        let total_collateral = (fee as f64 * params.collateral_percent).ceil() as u64;

        let collateral_return = PostAlonzoTransactionOutput {
            address: fuel_output.address.clone(),
            value: subtract(fuel_output.value.clone(), total_collateral).expect("not enough fuel"),
            datum_option: None,
            script_ref: None,
        };

        let votes = vec![(
            Voter::DRepScript(validator_hash),
            NonEmptyKeyValuePairs::Def(vec![(
                proposal_id.clone(),
                VotingProcedure {
                    vote: choice.clone(),
                    anchor: anchor.clone().map(Nullable::Some).unwrap_or(Nullable::Null),
                },
            )]),
        )];
        redeemers.push((
            RedeemersKey {
                tag: RedeemerTag::Vote,
                index: 0,
            },
            RedeemersValue {
                data: rules.clone(),
                ex_units: ex_units[0],
            },
        ));

        // ----- Put it all together
        let redeemers = non_empty_pairs(redeemers).unwrap();
        Tx {
            transaction_body: TransactionBody {
                inputs: Set::from(inputs),
                reference_inputs: non_empty_set(reference_inputs),
                network_id: Some(from_network(network.network_id())),
                outputs: into_outputs(outputs),
                voting_procedures: non_empty_pairs(votes),
                fee,
                collateral: non_empty_set(vec![fuel.clone()]),
                collateral_return: Some(PseudoTransactionOutput::PostAlonzo(collateral_return)),
                total_collateral: Some(total_collateral),
                required_signers: non_empty_set(delegates.clone()),
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
