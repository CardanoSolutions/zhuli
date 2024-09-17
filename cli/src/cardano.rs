use blockfrost::BlockfrostAPI;
use blockfrost_openapi::models::tx_content_output_amount_inner::TxContentOutputAmountInner;
use pallas_addresses::Network;
use pallas_codec::utils::NonEmptyKeyValuePairs;
use pallas_primitives::conway::{
    AssetName, PolicyId, PostAlonzoTransactionOutput, TransactionInput, Value,
};
use std::{collections::BTreeMap, env};

pub struct Cardano {
    api: BlockfrostAPI,
    network: Network,
}

const UNIT_LOVELACE: &str = "lovelace";

const ENV_PROJECT_ID: &str = "BLOCKFROST_PROJECT_ID";

#[derive(Debug)]
pub struct ProtocolParameters {
    pub collateral_percent: f64,
    pub drep_deposit: u64,
    pub fee_constant: u64,
    pub fee_coefficient: u64,
    pub price_mem: f64,
    pub price_steps: f64,
}

impl Cardano {
    pub fn new() -> Self {
        let project_id =
            env::var(ENV_PROJECT_ID).unwrap_or_else(|_| panic!("Missing {ENV_PROJECT_ID} env var"));
        let api = BlockfrostAPI::new(project_id.as_str(), Default::default());
        Cardano {
            api,
            network: if project_id.starts_with("mainnet") {
                Network::Mainnet
            } else {
                Network::Testnet
            },
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
            drep_deposit: 500_000_000, // NOTE: Missing from Blockfrost
            price_mem: params
                .price_mem
                .expect("protocol parameters are missing price mem") as f64,
            price_steps: params
                .price_step
                .expect("protocol parameters are missing price step")
                as f64,
            fee_constant: params.min_fee_b as u64,
            fee_coefficient: params.min_fee_a as u64,
        }
    }

    pub async fn resolve(&self, input: &TransactionInput) -> Option<PostAlonzoTransactionOutput> {
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

                // assert!(
                //     o.data_hash.is_none(),
                //     "non-null datum hash about to be ignored"
                // );

                PostAlonzoTransactionOutput {
                    address: from_bech32(&o.address).into(),
                    value: from_tx_content_output_amounts(&o.amount[..]),
                    datum_option: None,
                    script_ref: None,
                }
            })
    }
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
