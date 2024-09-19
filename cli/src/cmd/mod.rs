use crate::pallas_extra::OutputReference;
use clap::{Arg, ArgAction, ArgMatches, Command};
use pallas_codec::utils::Bytes;
use pallas_crypto::hash::{Hash, Hasher};
use pallas_primitives::conway::{Anchor, GovActionId, Vote};

mod delegate;
pub(crate) use delegate::{delegate, redelegate};

mod revoke;
pub(crate) use revoke::revoke;

mod vote;
pub(crate) use vote::vote;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) enum ParseFailure {
    OutputReference(&'static str, String),
    HexString(&'static str, hex::FromHexError),
    Int(&'static str, std::num::ParseIntError),
}

pub(crate) fn cli() -> Command {
    Command::new("zhuli")
        .version(clap::crate_version!())
        .about("A toolkit providing hot/cold account management for delegate representatives on Cardano.
This command-line serves as a transaction builder various steps of the contract.")
        .after_help(color_print::cstr!(
                    r#"<underline><bold>Important:</bold></underline>
  <italic>Blockfrost</italic> is used behind the scene to resolve information such as protocol parameters or UTxO.
  Therefore, you are expected to provide a valid <bold>BLOCKFROST_PROJECT_ID</bold> environment variable.
"#      ))
        .subcommand(vote::cmd())
        .subcommand(delegate::cmd())
        .subcommand(revoke::cmd())
}

// ----------------------------------------------------------- administrator ----

const ARG_ADMINISTRATOR: &str = "administrator";

fn arg_administrator() -> Arg {
    Arg::new(ARG_ADMINISTRATOR)
        .long(ARG_ADMINISTRATOR)
        .short('a')
        .value_name("HEX_STRING")
        .required(true)
        .help("Verification key hash digest (blake2b-228) of an admin signatory. Use multiple times for multiple admins.")
        .action(ArgAction::Append)
}

pub(crate) fn get_arg_administrators(args: &ArgMatches) -> Result<Vec<Hash<28>>, ParseFailure> {
    args.get_many::<String>(ARG_ADMINISTRATOR)
        .unwrap_or_default()
        .map(|admin| admin.parse())
        .collect::<Result<_, _>>()
        .map_err(|e| ParseFailure::HexString(ARG_ADMINISTRATOR, e))
}

// ----------------------------------------------------------------- anchor ----

const ARG_ANCHOR: &str = "anchor";

fn arg_anchor() -> Arg {
    Arg::new(ARG_ANCHOR)
        .long(ARG_ANCHOR)
        .short('a')
        .value_name("URL")
        .help("An (optional) URL to an anchor file containing rationale for the vote.")
        .action(ArgAction::Set)
}

pub(crate) async fn get_arg_anchor(args: &ArgMatches) -> Option<Anchor> {
    if let Some(url) = args.get_one::<String>(ARG_ANCHOR) {
        let response = reqwest::get(url)
            .await
            .expect("failed to fetch anchor at URL: {url}");
        match response.status() {
            status if status.is_success() => {
                let content_hash = Hasher::<256>::hash(response.bytes().await.unwrap().as_ref());
                Some(Anchor {
                    url: url.to_string(),
                    content_hash,
                })
            }
            status => panic!("failed to fetch anchor content, server said: {status:?}"),
        }
    } else {
        None
    }
}

// --------------------------------------------------------------- contract ----

const ARG_CONTRACT: &str = "contract";

fn arg_contract(required: bool) -> Arg {
    Arg::new(ARG_CONTRACT)
        .long(ARG_CONTRACT)
        .short('c')
        .value_name("TX_ID#IX")
        .help("The UTxO holding the contract's state.")
        .required(required)
        .action(ArgAction::Set)
}

pub(crate) fn get_arg_contract(args: &ArgMatches) -> Result<Option<OutputReference>, ParseFailure> {
    args.get_one::<String>(ARG_CONTRACT)
        .map(|s| s.parse())
        .transpose()
        .map_err(|e| ParseFailure::OutputReference(ARG_CONTRACT, e))
}

// --------------------------------------------------------------- delegate ----

const ARG_DELEGATE: &str = "delegate";

fn arg_delegate() -> Arg {
    Arg::new(ARG_DELEGATE)
        .long(ARG_DELEGATE)
        .short('d')
        .value_name("HEX_STRING")
        .help("Verification key hash digest (blake2b-228) of a delegate signatory. Use multiple times for multiple delegates.")
        .action(ArgAction::Append)
}

pub(crate) fn get_arg_delegates(args: &ArgMatches) -> Result<Vec<Hash<28>>, ParseFailure> {
    args.get_many::<String>(ARG_DELEGATE)
        .unwrap_or_default()
        .map(|delegate| delegate.parse())
        .collect::<Result<_, _>>()
        .map_err(|e| ParseFailure::HexString(ARG_DELEGATE, e))
}

// ------------------------------------------------------------------- fuel ----

const ARG_FUEL: &str = "fuel";

fn arg_fuel() -> Arg {
    Arg::new(ARG_FUEL)
        .long(ARG_FUEL)
        .short('f')
        .required(true)
        .value_name("TX_ID#IX")
        .help("A UTxO to use as fuel for the transaction. Must be suitable for collateral use.")
        .action(ArgAction::Set)
}

pub(crate) fn get_arg_fuel(args: &ArgMatches) -> Result<OutputReference, ParseFailure> {
    args.get_one::<String>(ARG_FUEL)
        .unwrap()
        .parse()
        .map_err(|e| ParseFailure::OutputReference(ARG_FUEL, e))
}

// --------------------------------------------------------------- proposal ----

const ARG_PROPOSAL: &str = "proposal";

fn arg_proposal() -> Arg {
    Arg::new(ARG_PROPOSAL)
        .long(ARG_PROPOSAL)
        .short('p')
        .required(true)
        .value_name("TX_ID#IX")
        .help("The proposal procedure identifier that's being voted on.")
        .action(ArgAction::Set)
}

pub(crate) fn get_arg_proposal(args: &ArgMatches) -> Result<GovActionId, ParseFailure> {
    let OutputReference(utxo_like) = args
        .get_one::<String>(ARG_PROPOSAL)
        .unwrap()
        .parse()
        .map_err(|e| ParseFailure::OutputReference(ARG_PROPOSAL, e))?;

    Ok(GovActionId {
        transaction_id: utxo_like.transaction_id,
        action_index: utxo_like.index as u32,
    })
}

// ----------------------------------------------------------------- quorum ----

const ARG_QUORUM: &str = "quorum";

fn arg_quorum() -> Arg {
    Arg::new(ARG_QUORUM)
        .long(ARG_QUORUM)
        .short('q')
        .value_name("UINT")
        .help("Minimum number of delegates to authorize votes. Default to the total number of delegates (plenum).")
        .action(ArgAction::Set)
}

pub(crate) fn get_arg_quorum(args: &ArgMatches) -> Result<Option<usize>, ParseFailure> {
    args.get_one::<String>(ARG_QUORUM)
        .map(|s| s.parse().map_err(|e| ParseFailure::Int(ARG_QUORUM, e)))
        .transpose()
}

// -------------------------------------------------------------- validator ----

const ARG_VALIDATOR: &str = "validator";

fn arg_validator() -> Arg {
    Arg::new(ARG_VALIDATOR)
        .long(ARG_VALIDATOR)
        .short('v')
        .value_name("HEX_STRING")
        .help("The compiled validator code, hex-encoded. (e.g jq -r '.validators[0].compiledCode' plutus.json)")
        .action(ArgAction::Set)
}

pub(crate) fn get_arg_validator(args: &ArgMatches) -> Result<Option<Bytes>, ParseFailure> {
    args.get_one::<String>(ARG_VALIDATOR)
        .map(|s| {
            hex::decode(s)
                .map(Bytes::from)
                .map_err(|e| ParseFailure::HexString(ARG_VALIDATOR, e))
        })
        .transpose()
}

// ------------------------------------------------------------------- vote ----

pub(crate) fn get_arg_vote(args: &ArgMatches) -> Vote {
    match args.get_one::<clap::Id>("vote").unwrap().as_str() {
        "yes" => Vote::Yes,
        "no" => Vote::No,
        "abstain" => Vote::Abstain,
        _ => unreachable!(),
    }
}

fn flag_yes() -> Arg {
    Arg::new("yes")
        .short('y')
        .long("yes")
        .help("Approve the governance proposal")
        .action(ArgAction::SetTrue)
}

fn flag_no() -> Arg {
    Arg::new("no")
        .short('n')
        .long("no")
        .help("Reject the governance proposal")
        .action(ArgAction::SetTrue)
}

fn flag_abstain() -> Arg {
    Arg::new("abstain")
        .long("abstain")
        .help("Abstain from the governance proposal voting")
        .action(ArgAction::SetTrue)
}
