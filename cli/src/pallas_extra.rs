use pallas_addresses::{Network, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart};
use pallas_codec::{
    minicbor as cbor,
    utils::{NonEmptyKeyValuePairs, NonEmptySet, Set},
};
use pallas_crypto::hash::{Hash, Hasher};
use pallas_primitives::conway::{
    AssetName, Constr, ExUnits, Language, Multiasset, NetworkId, PlutusData,
    PostAlonzoTransactionOutput, PseudoTransactionOutput, RedeemerTag, RedeemersKey,
    RedeemersValue, TransactionBody, TransactionInput, TransactionOutput, Tx, Value, WitnessSet,
};
use std::{cmp::Ordering, str::FromStr};
use uplc::tx::{eval_phase_two, ResolvedInput, SlotConfig};

#[derive(Debug)]
pub struct BuildParams {
    pub fee_constant: u64,
    pub fee_coefficient: u64,
    pub price_mem: f64,
    pub price_steps: f64,
}

pub struct OutputReference(pub TransactionInput);

impl FromStr for OutputReference {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s.split('#').collect::<Vec<_>>()[..] {
            [tx_id_str, ix_str] => {
                let transaction_id: Hash<32> = tx_id_str
                    .parse()
                    .map_err(|e| format!("failed to decode transaction id from hex: {e:?}"))?;
                let index: u64 = ix_str
                    .parse()
                    .map_err(|e| format!("failed to decode output index: {e:?}"))?;
                Ok(OutputReference(TransactionInput {
                    transaction_id,
                    index,
                }))
            }
            _ => Err("malformed output reference: expected a hex-encode string and an index separated by '#'".to_string()),
        }
    }
}

pub struct Redeemer {}

impl Redeemer {
    pub fn mint(index: u32, data: PlutusData, ex_units: ExUnits) -> (RedeemersKey, RedeemersValue) {
        (
            RedeemersKey {
                tag: RedeemerTag::Mint,
                index,
            },
            RedeemersValue { data, ex_units },
        )
    }

    pub fn spend(
        (inputs, target): (&[TransactionInput], &TransactionInput),
        data: PlutusData,
        ex_units: ExUnits,
    ) -> (RedeemersKey, RedeemersValue) {
        (
            RedeemersKey {
                tag: RedeemerTag::Spend,
                index: inputs
                    .iter()
                    .enumerate()
                    .find(|(_, i)| *i == target)
                    .unwrap()
                    .0 as u32,
            },
            RedeemersValue { data, ex_units },
        )
    }

    pub fn publish(
        index: u32,
        data: PlutusData,
        ex_units: ExUnits,
    ) -> (RedeemersKey, RedeemersValue) {
        (
            RedeemersKey {
                tag: RedeemerTag::Cert,
                index,
            },
            RedeemersValue { data, ex_units },
        )
    }

    pub fn vote(index: u32, data: PlutusData, ex_units: ExUnits) -> (RedeemersKey, RedeemersValue) {
        (
            RedeemersKey {
                tag: RedeemerTag::Vote,
                index,
            },
            RedeemersValue { data, ex_units },
        )
    }
}

pub fn void() -> PlutusData {
    PlutusData::Constr(Constr {
        tag: 121,
        any_constructor: None,
        fields: vec![],
    })
}

pub fn from_network(network: Network) -> NetworkId {
    match network {
        Network::Mainnet => NetworkId::Two,
        _ => NetworkId::One,
    }
}

pub fn non_empty_set<T>(set: Vec<T>) -> Option<NonEmptySet<T>>
where
    T: std::fmt::Debug,
{
    if set.is_empty() {
        None
    } else {
        Some(NonEmptySet::try_from(set).unwrap())
    }
}

pub fn non_empty_pairs<K, V>(pairs: Vec<(K, V)>) -> Option<NonEmptyKeyValuePairs<K, V>>
where
    V: Clone,
    K: Clone,
{
    if pairs.is_empty() {
        None
    } else {
        Some(NonEmptyKeyValuePairs::Def(pairs))
    }
}

pub fn into_outputs(outputs: Vec<PostAlonzoTransactionOutput>) -> Vec<TransactionOutput> {
    outputs
        .into_iter()
        .map(PseudoTransactionOutput::PostAlonzo)
        .collect()
}

pub fn singleton_assets<T: Clone>(
    validator_hash: Hash<28>,
    assets: &[(AssetName, T)],
) -> Multiasset<T> {
    NonEmptyKeyValuePairs::Def(vec![(
        validator_hash,
        NonEmptyKeyValuePairs::Def(assets.to_vec()),
    )])
}

pub fn from_validator(validator: &[u8], network_id: Network) -> (Hash<28>, ShelleyAddress) {
    let validator_hash = Hasher::<224>::hash_tagged(validator, 3);
    let validator_address = ShelleyAddress::new(
        network_id,
        ShelleyPaymentPart::script_hash(validator_hash),
        ShelleyDelegationPart::script_hash(validator_hash),
    );

    (validator_hash, validator_address)
}

pub fn value_subtract_lovelace(value: Value, lovelace: u64) -> Option<Value> {
    match value {
        Value::Coin(total) if total > lovelace => Some(Value::Coin(total - lovelace)),
        Value::Multiasset(total, assets) if total > lovelace => {
            Some(Value::Multiasset(total - lovelace, assets))
        }
        _ => None,
    }
}

pub fn value_add_lovelace(value: Value, lovelace: u64) -> Value {
    match value {
        Value::Coin(total) => Value::Coin(total + lovelace),
        Value::Multiasset(total, assets) => Value::Multiasset(total + lovelace, assets),
    }
}

pub fn lovelace_of(value: &Value) -> u64 {
    match value {
        Value::Coin(lovelace) | Value::Multiasset(lovelace, _) => *lovelace,
    }
}

pub fn new_min_value_output<F>(per_byte: u64, build: F) -> PostAlonzoTransactionOutput
where
    F: Fn(u64) -> PostAlonzoTransactionOutput,
{
    let value = build(1);
    let mut buffer: Vec<u8> = Vec::new();
    cbor::encode(&value, &mut buffer).unwrap();
    // NOTE: 160 overhead as per the spec + 4 bytes for actual final lovelace value.
    // Technically, the final value could need 8 more additional bytes if the resulting
    // value was larger than 4_294_967_295 lovelaces, which would realistically never be
    // the case.
    build((buffer.len() as u64 + 164) * per_byte)
}

pub fn total_execution_cost(params: &BuildParams, redeemers: &[ExUnits]) -> u64 {
    redeemers.iter().fold(0, |acc, ex_units| {
        acc + ((params.price_mem * ex_units.mem as f64).ceil() as u64)
            + ((params.price_steps * ex_units.steps as f64).ceil() as u64)
    })
}

pub fn script_integrity_hash(
    redeemers: Option<&NonEmptyKeyValuePairs<RedeemersKey, RedeemersValue>>,
    datums: Option<&NonEmptyKeyValuePairs<Hash<32>, PlutusData>>,
    language_views: &[(Language, &[i64])],
) -> Option<Hash<32>> {
    if redeemers.is_none() && language_views.is_empty() && datums.is_none() {
        return None;
    }

    let mut preimage: Vec<u8> = Vec::new();
    if let Some(redeemers) = redeemers {
        cbor::encode(redeemers, &mut preimage).unwrap();
    }

    if let Some(datums) = datums {
        cbor::encode(datums, &mut preimage).unwrap();
    }

    // NOTE: This doesn't work for PlutusV1, but I don't care.
    if !language_views.is_empty() {
        let mut views = language_views.to_vec();
        // TODO: Derive an Ord instance in Pallas.
        views.sort_by(|(a, _), (b, _)| match (a, b) {
            (Language::PlutusV3, Language::PlutusV3) => Ordering::Equal,
            (Language::PlutusV3, _) => Ordering::Greater,
            (_, Language::PlutusV3) => Ordering::Less,

            (Language::PlutusV2, Language::PlutusV2) => Ordering::Equal,
            (Language::PlutusV2, _) => Ordering::Greater,
            (_, Language::PlutusV2) => Ordering::Less,

            (Language::PlutusV1, Language::PlutusV1) => Ordering::Equal,
        });
        cbor::encode(NonEmptyKeyValuePairs::Def(views), &mut preimage).unwrap()
    }

    Some(Hasher::<256>::hash(&preimage))
}

pub fn default_transaction_body() -> TransactionBody {
    TransactionBody {
        auxiliary_data_hash: None,
        certificates: None,
        collateral: None,
        collateral_return: None,
        donation: None,
        fee: 0,
        inputs: Set::from(vec![]),
        mint: None,
        network_id: None,
        outputs: vec![],
        proposal_procedures: None,
        reference_inputs: None,
        required_signers: None,
        script_data_hash: None,
        total_collateral: None,
        treasury_value: None,
        ttl: None,
        validity_interval_start: None,
        voting_procedures: None,
        withdrawals: None,
    }
}

pub fn default_witness_set() -> WitnessSet {
    WitnessSet {
        bootstrap_witness: None,
        native_script: None,
        plutus_data: None,
        plutus_v1_script: None,
        plutus_v2_script: None,
        plutus_v3_script: None,
        redeemer: None,
        vkeywitness: None,
    }
}

// Build a transaction by repeatedly executing some building logic with different fee and execution
// units settings. Stops when a fixed point is reached. The final transaction has corresponding
// fees and execution units.
pub fn build_transaction<F>(params: &BuildParams, resolved_inputs: &[ResolvedInput], with: F) -> Tx
where
    F: Fn(u64, &[ExUnits]) -> Tx,
{
    let empty_ex_units = || {
        vec![
            ExUnits { mem: 0, steps: 0 },
            ExUnits { mem: 0, steps: 0 },
            ExUnits { mem: 0, steps: 0 },
            ExUnits { mem: 0, steps: 0 },
        ]
    };

    let mut fee = 0;
    let mut ex_units = empty_ex_units();

    let mut tx;
    let mut attempts = 0;
    loop {
        tx = with(fee, &ex_units[..]);

        // Convert to minted_tx...
        let mut serialized_tx = Vec::new();
        cbor::encode(&tx, &mut serialized_tx).unwrap();

        let mut calculated_ex_units = if resolved_inputs.is_empty() {
            empty_ex_units()
        } else {
            // Compute execution units
            let minted_tx = cbor::decode(&serialized_tx).unwrap();
            eval_phase_two(
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
            .collect::<Vec<_>>()
        };

        calculated_ex_units.extend(empty_ex_units());

        attempts += 1;

        let estimated_fee = {
            // NOTE: This is a best effort to estimate the number of signatories since signatures
            // will add an overhead to the fee. Yet, if inputs are locked by native scripts each
            // requiring multiple signatories, this will unfortunately fall short.
            //
            // For similar reasons, it will also over-estimate fees by a small margin for every
            // script-locked inputs that do not require signatories.
            //
            // This is however *acceptable* in our context.
            let num_signatories = tx.transaction_body.inputs.len()
                + tx.transaction_body
                    .required_signers
                    .as_ref()
                    .map(|xs| xs.len())
                    .unwrap_or(0);

            params.fee_constant
                + params.fee_coefficient
                    * (5 + ex_units.len() * 16 + num_signatories * 102 + serialized_tx.len()) as u64
                + total_execution_cost(params, &ex_units)
        };

        // Check if we've reached a fixed point, or start over.
        if fee >= estimated_fee
            && calculated_ex_units
                .iter()
                .zip(ex_units)
                .all(|(l, r)| l.eq(&r))
        {
            break;
        } else if attempts >= 3 {
            panic!("failed to build transaction: did not converge after three attempts.");
        } else {
            ex_units = calculated_ex_units;
            fee = estimated_fee;
        }
    }

    tx
}

pub fn expect_post_alonzo(output: &TransactionOutput) -> &PostAlonzoTransactionOutput {
    if let TransactionOutput::PostAlonzo(ref o) = output {
        o
    } else {
        panic!("expected PostAlonzo output but got a legacy one.")
    }
}
