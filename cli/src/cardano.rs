use crate::pallas_extra::BuildParams;
use blockfrost::{BlockfrostAPI, Pagination};
use blockfrost_openapi::models::{
    asset_history_inner::Action, tx_content_output_amount_inner::TxContentOutputAmountInner,
};
use pallas_addresses::Network;
use pallas_codec::{minicbor as cbor, utils::NonEmptyKeyValuePairs};
use pallas_primitives::conway::{
    AssetName, PolicyId, PostAlonzoTransactionOutput, TransactionInput, TransactionOutput, Tx,
    Value,
};
use std::{collections::BTreeMap, env};
use uplc::tx::ResolvedInput;

pub struct Cardano {
    api: BlockfrostAPI,
    client: reqwest::Client,
    network: Network,
    network_prefix: String,
    project_id: String,
}

const UNIT_LOVELACE: &str = "lovelace";

const MAINNET_PREFIX: &str = "mainnet";
const PREPROD_PREFIX: &str = "preprod";
const PREVIEW_PREFIX: &str = "preview";

const ENV_PROJECT_ID: &str = "BLOCKFROST_PROJECT_ID";

#[derive(Debug)]
pub struct ProtocolParameters {
    pub collateral_percent: f64,
    pub cost_model_v3: Vec<i64>,
    pub drep_deposit: u64,
    pub fee_constant: u64,
    pub fee_coefficient: u64,
    pub min_utxo_deposit_coefficient: u64,
    pub price_mem: f64,
    pub price_steps: f64,
}

impl From<&ProtocolParameters> for BuildParams {
    fn from(params: &ProtocolParameters) -> BuildParams {
        BuildParams {
            fee_constant: params.fee_constant,
            fee_coefficient: params.fee_coefficient,
            price_mem: params.price_mem,
            price_steps: params.price_steps,
        }
    }
}

impl Cardano {
    pub fn new() -> Self {
        let project_id =
            env::var(ENV_PROJECT_ID).unwrap_or_else(|_| panic!("Missing {ENV_PROJECT_ID} env var"));
        let api = BlockfrostAPI::new(project_id.as_str(), Default::default());
        Cardano {
            api,
            client: reqwest::Client::new(),
            network: if project_id.starts_with(MAINNET_PREFIX) {
                Network::Mainnet
            } else {
                Network::Testnet
            },
            network_prefix: if project_id.starts_with(MAINNET_PREFIX) {
                MAINNET_PREFIX.to_string()
            } else if project_id.starts_with(PREPROD_PREFIX) {
                PREPROD_PREFIX.to_string()
            } else if project_id.starts_with(PREVIEW_PREFIX) {
                PREVIEW_PREFIX.to_string()
            } else {
                panic!("unexpected project id prefix")
            },
            project_id,
        }
    }

    pub fn network_id(&self) -> Network {
        self.network
    }

    pub async fn protocol_parameters(&self) -> ProtocolParameters {
        let params = self
            .api
            .epochs_latest_parameters()
            .await
            .expect("failed to fetch protocol parameters");

        ProtocolParameters {
            collateral_percent: (params
                .collateral_percent
                .expect("protocol parameters are missing collateral percent")
                as f64)
                / 1e2,
            // NOTE: Blockfrost returns cost models out of order. They must be ordered by their
            // "ParamName" according to how Plutus defines it, but they are usually found ordered
            // by ascending keys, unfortunately. Given that they are unlikely to change anytime
            // soon, I am going to bundle them as-is.
            cost_model_v3: vec![
                100788, 420, 1, 1, 1000, 173, 0, 1, 1000, 59957, 4, 1, 11183, 32, 201305, 8356, 4,
                16000, 100, 16000, 100, 16000, 100, 16000, 100, 16000, 100, 16000, 100, 100, 100,
                16000, 100, 94375, 32, 132994, 32, 61462, 4, 72010, 178, 0, 1, 22151, 32, 91189,
                769, 4, 2, 85848, 123203, 7305, -900, 1716, 549, 57, 85848, 0, 1, 1, 1000, 42921,
                4, 2, 24548, 29498, 38, 1, 898148, 27279, 1, 51775, 558, 1, 39184, 1000, 60594, 1,
                141895, 32, 83150, 32, 15299, 32, 76049, 1, 13169, 4, 22100, 10, 28999, 74, 1,
                28999, 74, 1, 43285, 552, 1, 44749, 541, 1, 33852, 32, 68246, 32, 72362, 32, 7243,
                32, 7391, 32, 11546, 32, 85848, 123203, 7305, -900, 1716, 549, 57, 85848, 0, 1,
                90434, 519, 0, 1, 74433, 32, 85848, 123203, 7305, -900, 1716, 549, 57, 85848, 0, 1,
                1, 85848, 123203, 7305, -900, 1716, 549, 57, 85848, 0, 1, 955506, 213312, 0, 2,
                270652, 22588, 4, 1457325, 64566, 4, 20467, 1, 4, 0, 141992, 32, 100788, 420, 1, 1,
                81663, 32, 59498, 32, 20142, 32, 24588, 32, 20744, 32, 25933, 32, 24623, 32,
                43053543, 10, 53384111, 14333, 10, 43574283, 26308, 10, 16000, 100, 16000, 100,
                962335, 18, 2780678, 6, 442008, 1, 52538055, 3756, 18, 267929, 18, 76433006, 8868,
                18, 52948122, 18, 1995836, 36, 3227919, 12, 901022, 1, 166917843, 4307, 36, 284546,
                36, 158221314, 26549, 36, 74698472, 36, 333849714, 1, 254006273, 72, 2174038, 72,
                2261318, 64571, 4, 207616, 8310, 4, 1293828, 28716, 63, 0, 1, 1006041, 43623, 251,
                0, 1,
            ],
            drep_deposit: 500_000_000, // NOTE: Missing from Blockfrost
            fee_constant: params.min_fee_b as u64,
            fee_coefficient: params.min_fee_a as u64,
            min_utxo_deposit_coefficient: params
                .coins_per_utxo_size
                .expect("protocol parameters are missing min utxo deposit coefficient")
                .parse()
                .unwrap(),
            price_mem: params
                .price_mem
                .expect("protocol parameters are missing price mem") as f64,
            price_steps: params
                .price_step
                .expect("protocol parameters are missing price step")
                as f64,
        }
    }

    pub async fn minting(&self, policy_id: &PolicyId, asset_name: &AssetName) -> Vec<Tx> {
        let history = self
            .api
            .assets_history(
                &format!("{}{}", hex::encode(policy_id), hex::encode(&asset_name[..])),
                Pagination::all(),
            )
            .await
            .ok()
            .unwrap_or(vec![])
            .into_iter()
            .filter_map(|inner| {
                if matches!(inner.action, Action::Minted) {
                    Some(inner.tx_hash)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let mut txs: Vec<Tx> = vec![];
        for tx_hash in history {
            if let Some(tx) = self.transaction_by_hash(&tx_hash).await {
                txs.push(tx)
            }
        }
        txs
    }

    pub async fn transaction_by_hash(&self, tx_hash: &str) -> Option<Tx> {
        // NOTE: Not part of the Rust SDK somehow...
        let response = self
            .client
            .get(&format!(
                "https://cardano-{}.blockfrost.io/api/v0/txs/{}/cbor",
                self.network_prefix, tx_hash
            ))
            .header("Accept", "application/json")
            .header("project_id", self.project_id.as_str())
            .send()
            .await
            .unwrap();

        match response.status() {
            reqwest::StatusCode::OK => {
                let TxByHash { cbor } = response.json::<TxByHash>().await.unwrap();
                let tx = cbor::decode(&hex::decode(cbor).unwrap()).unwrap();
                Some(tx)
            }
            _ => None,
        }
    }

    pub async fn resolve_many(&self, inputs: &[&TransactionInput]) -> Vec<ResolvedInput> {
        let mut resolved = vec![];
        for i in inputs {
            if let Some(r) = self.resolve(i).await {
                resolved.push(r)
            }
        }
        resolved
    }

    pub async fn resolve(&self, input: &TransactionInput) -> Option<ResolvedInput> {
        let utxo = self
            .api
            .transactions_utxos(hex::encode(input.transaction_id).as_str())
            .await
            .ok()?;

        utxo.outputs
            .into_iter()
            .filter(|o| !o.collateral)
            .nth(input.index as usize)
            .map(|o| {
                assert_eq!(
                    o.output_index, input.index as i32,
                    "somehow resolved the wrong ouput",
                );

                assert!(
                    o.reference_script_hash.is_none(),
                    "non-null reference script about to be ignored"
                );

                assert!(
                    o.data_hash.is_none(),
                    "non-null datum hash about to be ignored"
                );

                ResolvedInput {
                    input: input.clone(),
                    output: TransactionOutput::PostAlonzo(PostAlonzoTransactionOutput {
                        address: from_bech32(&o.address).into(),
                        value: from_tx_content_output_amounts(&o.amount[..]),
                        datum_option: None,
                        script_ref: None,
                    }),
                }
            })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct TxByHash {
    cbor: String,
}

fn from_bech32(bech32: &str) -> Vec<u8> {
    bech32::decode(bech32).unwrap().1
}

fn from_tx_content_output_amounts(xs: &[TxContentOutputAmountInner]) -> Value {
    let mut lovelaces = 0;
    let mut assets = BTreeMap::new();

    for asset in xs {
        let quantity: u64 = asset.quantity.parse().unwrap();
        if asset.unit == UNIT_LOVELACE {
            lovelaces += quantity;
        } else {
            let policy_id: PolicyId = asset.unit[0..56].parse().unwrap();
            let asset_name: AssetName = hex::decode(&asset.unit[56..]).unwrap().into();
            assets
                .entry(policy_id)
                .and_modify(|m: &mut BTreeMap<AssetName, u64>| {
                    m.entry(asset_name.clone())
                        .and_modify(|q| *q += quantity)
                        .or_insert(quantity);
                })
                .or_insert_with(|| BTreeMap::from([(asset_name, quantity)]));
        }
    }

    if assets.is_empty() {
        Value::Coin(lovelaces)
    } else {
        Value::Multiasset(
            lovelaces,
            NonEmptyKeyValuePairs::Def(
                assets
                    .into_iter()
                    .map(|(policy_id, policies)| {
                        (
                            policy_id,
                            NonEmptyKeyValuePairs::Def(
                                policies
                                    .into_iter()
                                    .map(|(asset_name, quantity)| {
                                        (asset_name, quantity.try_into().unwrap())
                                    })
                                    .collect::<Vec<_>>(),
                            ),
                        )
                    })
                    .collect::<Vec<_>>(),
            ),
        )
    }
}
