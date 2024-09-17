use crate::cardano::ProtocolParameters;
use cardano::Cardano;
use clap::{Arg, ArgAction, Command};
use indoc::printdoc;
use pallas_addresses::{Network, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart};
use pallas_codec::{
    minicbor as cbor,
    utils::{Bytes, NonEmptyKeyValuePairs, NonEmptySet, NonZeroInt, Nullable, PositiveCoin, Set},
};
use pallas_crypto::hash::{Hash, Hasher};
use pallas_primitives::conway::{
    AssetName, Certificate, Constr, ExUnits, Multiasset, NetworkId, PlutusData, PlutusV3Script,
    PostAlonzoTransactionOutput, PseudoTransactionOutput, RedeemerTag, RedeemersKey,
    RedeemersValue, StakeCredential, TransactionBody, TransactionInput, Tx, Value, WitnessSet,
};
use std::{num, str::FromStr};
use uplc::tx::{eval_phase_two, ResolvedInput, SlotConfig};

mod cardano;

// ------------------------------------------------------------------ main ----

const CONTRACT_LOCKED_FUND: u64 = 1_000_000;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let network = Cardano::new();

    match cli().get_matches().subcommand() {
        Some(("delegate", args)) => {
            let validator = hex::decode(args.get_one::<String>("validator").unwrap())
                .map_err(|e| Error::FailedToDecodeHexString("validator", e))?
                .into();

            let administrators = args
                .get_many::<String>("administrator")
                .unwrap_or_default()
                .map(|admin| admin.parse())
                .collect::<Result<Vec<Hash<28>>, _>>()
                .map_err(|e| Error::FailedToDecodeHexString("administrator", e))?;

            let delegates = args
                .get_many::<String>("delegate")
                .unwrap_or_default()
                .map(|delegate| delegate.parse())
                .collect::<Result<Vec<Hash<28>>, _>>()
                .map_err(|e| Error::FailedToDecodeHexString("delegate", e))?;

            let quorum = args
                .get_one::<String>("quorum")
                .map(|s| s.parse().map_err(|e| Error::FailedToDecodeInt("quorum", e)))
                .transpose()?
                .unwrap_or(delegates.len());

            let fuel = args.get_one::<String>("fuel").unwrap().parse()?;

            report(delegate(network, validator, administrators, delegates, quorum, fuel).await?)
        }

        Some(("vote", _)) => Ok(()),

        Some(("revoke", _)) => Ok(()),

        _ => unreachable!(),
    }
}

struct OutputReference(TransactionInput);

impl FromStr for OutputReference {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s.split('#').collect::<Vec<_>>()[..] {
            [tx_id_str, ix_str] => {
                let transaction_id: Hash<32> = tx_id_str
                    .parse()
                    .map_err(|e| Error::FailedToDecodeHexString("transaction id", e))?;
                let index: u64 = ix_str
                    .parse()
                    .map_err(|e| Error::FailedToDecodeInt("output index", e))?;
                Ok(OutputReference(TransactionInput {
                    transaction_id,
                    index,
                }))
            }
            _ => Err(Error::MalformedOutputReference),
        }
    }
}

// ---------------------------------------------------------------- errors ----

#[allow(dead_code)]
#[derive(Debug, Clone)]
enum Error {
    FailedToDecodeHexString(&'static str, hex::FromHexError),
    MalformedOutputReference,
    FailedToDecodeInt(&'static str, num::ParseIntError),
}

// -------------------------------------------------------------- commands ----

fn report<E>(tx: Tx) -> Result<(), E> {
    let mut buf = Vec::new();
    cbor::encode(tx, &mut buf).unwrap();
    printdoc! {
        r#"{{
          "type": "Unwitnessed Tx ConwayEra",
          "description": "Ledger Cddl Format",
          "cborHex": "{}"
        }}"#,
        hex::encode(&buf),
    };
    Ok(())
}

async fn delegate(
    network: Cardano,
    validator: Bytes,
    administrators: Vec<Hash<28>>,
    delegates: Vec<Hash<28>>,
    quorum: usize,
    OutputReference(fuel): OutputReference,
) -> Result<Tx, Error> {
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

    build_transaction(&params, resolved_inputs, |fee, ex_units| {
        let execution_cost = total_execution_cost(&params, ex_units);

        let total_cost = CONTRACT_LOCKED_FUND + params.drep_deposit + execution_cost as u64 + fee;

        let total_collateral = (execution_cost as f64 * params.collateral_percent).ceil() as u64;

        let mut redeemers = vec![];

        let inputs = vec![fuel.clone()];

        let (rules, asset_name) = build_rules(&delegates[..], quorum);

        let outputs = vec![
            // Contract
            PostAlonzoTransactionOutput {
                address: validator_address.to_vec().into(),
                value: Value::Multiasset(
                    CONTRACT_LOCKED_FUND,
                    singleton_assets(
                        validator_hash,
                        &[(asset_name.clone(), PositiveCoin::try_from(1).unwrap())],
                    ),
                ),
                datum_option: None,
                script_ref: None,
            },
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
        Tx {
            transaction_body: new_transaction_body(
                network.network_id(),
                inputs,
                outputs,
                mint,
                certificates,
                (vec![fuel.clone()], collateral_return, total_collateral),
                fee,
                administrators.clone(),
            ),
            transaction_witness_set: new_witness_set(redeemers, validator.clone()),
            success: true,
            auxiliary_data: Nullable::Null,
        }
    })
}

// Build a transaction by repeatedly executing some building logic with different fee and execution
// units settings. Stops when a fixed point is reached. The final transaction has corresponding
// fees and execution units.
fn build_transaction<E, F>(
    params: &ProtocolParameters,
    resolved_inputs: &[ResolvedInput],
    with: F,
) -> Result<Tx, E>
where
    F: Fn(u64, &[ExUnits]) -> Tx,
{
    let mut fee = 0;
    let mut ex_units = vec![ExUnits { mem: 0, steps: 0 }, ExUnits { mem: 0, steps: 0 }];

    let mut tx;

    loop {
        tx = with(fee, &ex_units[..]);

        // Convert to minted_tx...
        let mut buffer = Vec::new();
        cbor::encode(&tx, &mut buffer).unwrap();
        let minted_tx = cbor::decode(&buffer).unwrap();

        // Compute execution units
        let calculated_ex_units = eval_phase_two(
            &minted_tx,
            resolved_inputs,
            None,
            None,
            &SlotConfig::default(),
            false,
            |_| (),
        )
        .expect("script evaluation failed")
        .into_iter()
        .map(|r| r.ex_units)
        .collect::<Vec<_>>();

        // Check if we've reached a fixed point, or start over.
        if calculated_ex_units == ex_units {
            break;
        } else {
            ex_units = calculated_ex_units;
            fee = buffer.len() as u64 * params.fee_coefficient + params.fee_constant;
        }
    }

    Ok(tx)
}

// ------------------------------------------------------------------- cli ----

fn cli() -> Command {
    Command::new("Hot/Cold DRep Management")
        .version("1.0.0")
        .about("A toolkit providing hot/cold account management for delegate representatives on Cardano.
This command-line serves as a transaction builder various steps of the contract.")
        .subcommand(
            Command::new("vote")
                .about("Vote on a governance action")
        )
        .subcommand(
            Command::new("delegate")
                .about("Hand-over voting rights to a delegate script.")
                .arg(arg_validator())
                .arg(arg_delegate())
                .arg(arg_administrator())
                .arg(arg_quorum())
                .arg(arg_contract())
                .arg(arg_fuel())
        )
        .subcommand(
            Command::new("revoke")
                .about("Revoke delegation, without defining a new delegate.")
        )
}

// ------------------------------------------------------------- arguments ----

fn arg_validator() -> Arg {
    Arg::new("validator")
        .long("validator")
        .short('v')
        .value_name("STRING::HEX")
        .help("The compiled validator code, hex-encoded. (e.g jq -r 'validators[0].compiledCode' plutus.json)")
        .action(ArgAction::Set)
}

fn arg_contract() -> Arg {
    Arg::new("contract")
        .long("contract")
        .short('c')
        .value_name("TX_ID#IX")
        .help("The UTxO holding the contract's state.")
        .action(ArgAction::Set)
}

fn arg_fuel() -> Arg {
    Arg::new("fuel")
        .long("fuel")
        .short('f')
        .required(true)
        .value_name("TX_ID#IX")
        .help("A UTxO to use as fuel for the transaction.")
        .action(ArgAction::Set)
}

fn arg_delegate() -> Arg {
    Arg::new("delegate")
        .long("delegate")
        .short('s')
        .value_name("STRING::HEX")
        .help("Verification key hash digest (blake2b-228) of a delegate signatory. Use multiple times for multiple delegates.")
        .action(ArgAction::Append)
}

fn arg_administrator() -> Arg {
    Arg::new("administrator")
        .long("administrator")
        .short('a')
        .value_name("STRING::HEX")
        .help("Verification key hash digest (blake2b-228) of an administrator signatory. Use multiple times for multiple administrators.")
        .action(ArgAction::Append)
}

fn arg_quorum() -> Arg {
    Arg::new("quorum")
        .long("quorum")
        .short('q')
        .value_name("UINT")
        .help("Minimum number of delegates to authorize votes. Default to the total number of delegates (plenum).")
        .action(ArgAction::Set)
}

// ---------------------------------------------------------------- helpers ----

#[allow(clippy::too_many_arguments)]
fn new_transaction_body(
    network_id: Network,
    inputs: Vec<TransactionInput>,
    outputs: Vec<PostAlonzoTransactionOutput>,
    mint: Multiasset<NonZeroInt>,
    certificates: Vec<Certificate>,
    (collateral, collateral_return, total_collateral): (
        Vec<TransactionInput>,
        PostAlonzoTransactionOutput,
        u64,
    ),
    fee: u64,
    extra_signatories: Vec<Hash<28>>,
) -> TransactionBody {
    TransactionBody {
        inputs: Set::from(inputs),
        reference_inputs: None,
        outputs: outputs
            .into_iter()
            .map(PseudoTransactionOutput::PostAlonzo)
            .collect(),
        fee,
        required_signers: NonEmptySet::try_from(extra_signatories).ok(),
        mint: Some(mint),
        certificates: Some(NonEmptySet::try_from(certificates).unwrap()),
        collateral: Some(NonEmptySet::try_from(collateral).unwrap()),
        collateral_return: Some(PseudoTransactionOutput::PostAlonzo(collateral_return)),
        total_collateral: Some(total_collateral),
        network_id: Some(match network_id {
            Network::Mainnet => NetworkId::Two,
            _ => NetworkId::One,
        }),
        // TODO ---------------
        script_data_hash: None,
        // --------------------
        ttl: None,
        validity_interval_start: None,
        withdrawals: None,
        auxiliary_data_hash: None,
        voting_procedures: None,
        proposal_procedures: None,
        treasury_value: None,
        donation: None,
    }
}

fn new_witness_set(redeemers: Vec<(RedeemersKey, RedeemersValue)>, validator: Bytes) -> WitnessSet {
    WitnessSet {
        vkeywitness: None,
        native_script: None,
        bootstrap_witness: None,
        plutus_v1_script: None,
        plutus_data: None,
        redeemer: Some(NonEmptyKeyValuePairs::Def(redeemers).into()),
        plutus_v2_script: None,
        plutus_v3_script: Some(NonEmptySet::try_from(vec![PlutusV3Script(validator)]).unwrap()),
    }
}

fn void() -> PlutusData {
    PlutusData::Constr(Constr {
        tag: 121,
        any_constructor: None,
        fields: vec![],
    })
}

fn build_rules(delegates: &[Hash<28>], quorum: usize) -> (PlutusData, AssetName) {
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
fn singleton_assets<T: Clone>(
    validator_hash: Hash<28>,
    assets: &[(AssetName, T)],
) -> Multiasset<T> {
    NonEmptyKeyValuePairs::Def(vec![(
        validator_hash,
        NonEmptyKeyValuePairs::Def(assets.to_vec()),
    )])
}

fn from_validator(validator: &[u8], network_id: Network) -> (Hash<28>, ShelleyAddress) {
    let validator_hash = Hasher::<224>::hash_tagged(validator, 3);
    let validator_address = ShelleyAddress::new(
        network_id,
        ShelleyPaymentPart::script_hash(validator_hash),
        ShelleyDelegationPart::script_hash(validator_hash),
    );

    (validator_hash, validator_address)
}

fn subtract(total_value: Value, total_cost: u64) -> Option<Value> {
    match total_value {
        Value::Coin(total) if total > total_cost => Some(Value::Coin(total - total_cost)),
        Value::Multiasset(total, assets) if total > total_cost => {
            Some(Value::Multiasset(total - total_cost, assets))
        }
        _ => None,
    }
}

fn total_execution_cost(params: &ProtocolParameters, redeemers: &[ExUnits]) -> u64 {
    redeemers.iter().fold(0, |acc, ex_units| {
        acc + ((params.price_mem * ex_units.mem as f64).ceil() as u64)
            + ((params.price_steps * ex_units.steps as f64).ceil() as u64)
    })
}
