use crate::{cardano::Cardano, contract::*, pallas_extra::*};
use clap::{ArgGroup, Command};
use pallas_codec::utils::{NonEmptyKeyValuePairs, Nullable, Set};
use pallas_crypto::hash::Hash;
use pallas_primitives::conway::{
    Anchor, GovActionId, Language, PlutusV3Script, PostAlonzoTransactionOutput,
    PseudoTransactionOutput, TransactionBody, Tx, Vote, Voter, VotingProcedure, WitnessSet,
};

pub(crate) fn cmd() -> Command {
    Command::new("vote")
        .about("Vote on a governance action.")
        .after_help(color_print::cstr!(
            r#"<underline><bold>Notes:</bold></underline>
  1. The specified <bold>--delegate</bold> must reflect the signatories for the transaction, but not necessarily ALL delegates.
     Only those authorizing the transaction must be present. And, there must be enough signatories for a quorum.

<underline><bold>Example:</bold></underline>
  <bold>vote</bold> \
    <bold>--yes</bold> \
    <bold>--proposal</bold> "2ad082a4f85d4a66e8bb240ecd147a8351228ebd0995bef90c4d14f61d4b19cc#0" \
    <bold>--anchor</bold> "https://metadata.cardanoapi.io/data/climate" \
    <bold>--delegate</bold> 000000000000000000000000000000000000000000000000000a11ce \
    <bold>--contract</bold> "8d5726c0e7cb207a3f5881d29a7ceba71f578c2165a2261340c242bdba6875dd#0" \
    <bold>--fuel</bold> "ab5334d2db6f7909b511ee9c0f7181c7f4da515ba15f186d95caef0d91ac4a11#0"
"#              ))
        .arg(super::arg_proposal())
        .arg(super::arg_anchor())
        .arg(super::flag_yes())
        .arg(super::flag_no())
        .arg(super::flag_abstain())
        .arg(super::arg_delegate())
        .arg(super::arg_contract(true))
        .arg(super::arg_fuel())
        .group(ArgGroup::new("vote")
            .args(["yes", "no", "abstain"])
            .multiple(false)
            .required(true)
        )
}

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

    let resolved_inputs = network.resolve_many(&[&fuel, &contract]).await;
    let fuel_output = expect_post_alonzo(&resolved_inputs[0].output);
    let contract_output = expect_post_alonzo(&resolved_inputs[1].output);

    let (rules, _) = recover_rules(&network, &validator_hash, &contract_output.value).await;

    build_transaction(
        &BuildParams::from(&params),
        &resolved_inputs[..],
        |fee, ex_units| {
            let mut redeemers = vec![];

            let inputs = vec![fuel.clone()];

            let reference_inputs = vec![contract.clone()];

            let outputs = vec![
                // Change
                PostAlonzoTransactionOutput {
                    address: fuel_output.address.clone(),
                    value: value_subtract_lovelace(fuel_output.value.clone(), fee)
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
            redeemers.push(Redeemer::vote(0, rules.clone(), ex_units[0]));

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
        },
    )
}
