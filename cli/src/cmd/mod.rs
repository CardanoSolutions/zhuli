use crate::pallas_extra::OutputReference;
use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command};
use indoc::indoc;
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
    Command::new("Hot/Cold DRep Management")
        .version("1.0.0")
        .about("A toolkit providing hot/cold account management for delegate representatives on Cardano.
This command-line serves as a transaction builder various steps of the contract.")
        .subcommand(
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
    <bold>--anchor</bold> "https://metadata.cardanoapi.io/data/climate \
    <bold>--delegate</bold> 000000000000000000000000000000000000000000000000000a11ce \
    <bold>--contract</bold> "8d5726c0e7cb207a3f5881d29a7ceba71f578c2165a2261340c242bdba6875dd#0" \
    <bold>--fuel</bold> "ab5334d2db6f7909b511ee9c0f7181c7f4da515ba15f186d95caef0d91ac4a11#0"
"#              ))
                .arg(arg_proposal())
                .arg(arg_anchor())
                .arg(flag_yes())
                .arg(flag_no())
                .arg(flag_abstain())
                .arg(arg_delegate())
                .arg(arg_contract(true))
                .arg(arg_fuel())
                .group(ArgGroup::new("vote")
                    .args(["yes", "no", "abstain"])
                    .multiple(false)
                    .required(true)
                )

        )
        .subcommand(
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
                .arg(arg_delegate())
                .arg(arg_quorum())
                .arg(arg_validator())
                .arg(arg_contract(false))
                .arg(arg_administrator())
                .arg(arg_fuel())
                .group(ArgGroup::new("source")
                    .args(["contract", "validator"])
                    .multiple(false)
                    .required(true)
                )
        )
        .subcommand(
            Command::new("revoke")
                .about("Revoke delegation, without defining a new delegate.")
        )
}

// --------------------------------------------------------- options & flags ----

// ----------------------------------------------------------- administrator ----

const ARG_ADMINISTRATOR: &str = "administrator";

fn arg_administrator() -> Arg {
    Arg::new(ARG_ADMINISTRATOR)
        .long(ARG_ADMINISTRATOR)
        .short('a')
        .value_name("HEX_STRING")
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

fn arg_anchor() -> Arg {
    Arg::new("anchor")
        .long("anchor")
        .short('a')
        .value_name("URL")
        .help("An (optional) URL to an anchor file containing rationale for the vote.")
        .action(ArgAction::Set)
}

pub(crate) async fn get_arg_anchor(args: &ArgMatches) -> Option<Anchor> {
    if let Some(url) = args.get_one::<String>("anchor") {
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

fn arg_contract(required: bool) -> Arg {
    Arg::new("contract")
        .long("contract")
        .short('c')
        .value_name("TX_ID#IX")
        .help("The UTxO holding the contract's state.")
        .required(required)
        .action(ArgAction::Set)
}

pub(crate) fn get_arg_contract(args: &ArgMatches) -> Result<Option<OutputReference>, ParseFailure> {
    args.get_one::<String>("contract")
        .map(|s| s.parse())
        .transpose()
        .map_err(|e| ParseFailure::OutputReference("contract", e))
}

// --------------------------------------------------------------- delegate ----

fn arg_delegate() -> Arg {
    Arg::new("delegate")
        .long("delegate")
        .short('d')
        .value_name("HEX_STRING")
        .help("Verification key hash digest (blake2b-228) of a delegate signatory. Use multiple times for multiple delegates.")
        .action(ArgAction::Append)
}

pub(crate) fn get_arg_delegates(args: &ArgMatches) -> Result<Vec<Hash<28>>, ParseFailure> {
    args.get_many::<String>("delegate")
        .unwrap_or_default()
        .map(|delegate| delegate.parse())
        .collect::<Result<_, _>>()
        .map_err(|e| ParseFailure::HexString("delegate", e))
}

// ------------------------------------------------------------------- fuel ----

fn arg_fuel() -> Arg {
    Arg::new("fuel")
        .long("fuel")
        .short('f')
        .required(true)
        .value_name("TX_ID#IX")
        .help("A UTxO to use as fuel for the transaction. Must be suitable for collateral use.")
        .action(ArgAction::Set)
}

pub(crate) fn get_arg_fuel(args: &ArgMatches) -> Result<OutputReference, ParseFailure> {
    args.get_one::<String>("fuel")
        .unwrap()
        .parse()
        .map_err(|e| ParseFailure::OutputReference("fuel", e))
}

// --------------------------------------------------------------- proposal ----

fn arg_proposal() -> Arg {
    Arg::new("proposal")
        .long("proposal")
        .short('p')
        .required(true)
        .value_name("TX_ID#IX")
        .help("The proposal procedure identifier that's being voted on.")
        .action(ArgAction::Set)
}

pub(crate) fn get_arg_proposal(args: &ArgMatches) -> Result<GovActionId, ParseFailure> {
    let OutputReference(utxo_like) = args
        .get_one::<String>("proposal")
        .unwrap()
        .parse()
        .map_err(|e| ParseFailure::OutputReference("proposal", e))?;

    Ok(GovActionId {
        transaction_id: utxo_like.transaction_id,
        action_index: utxo_like.index as u32,
    })
}

// ----------------------------------------------------------------- quorum ----

fn arg_quorum() -> Arg {
    Arg::new("quorum")
        .long("quorum")
        .short('q')
        .value_name("UINT")
        .help("Minimum number of delegates to authorize votes. Default to the total number of delegates (plenum).")
        .action(ArgAction::Set)
}

pub(crate) fn get_arg_quorum(args: &ArgMatches) -> Result<Option<usize>, ParseFailure> {
    args.get_one::<String>("quorum")
        .map(|s| s.parse().map_err(|e| ParseFailure::Int("quorum", e)))
        .transpose()
}

// -------------------------------------------------------------- validator ----

fn arg_validator() -> Arg {
    Arg::new("validator")
        .long("validator")
        .short('v')
        .value_name("HEX_STRING")
        .help("The compiled validator code, hex-encoded. (e.g jq -r '.validators[0].compiledCode' plutus.json)")
        .action(ArgAction::Set)
}

pub(crate) fn get_arg_validator(args: &ArgMatches) -> Result<Option<Bytes>, ParseFailure> {
    args.get_one::<String>("validator")
        .map(|s| {
            hex::decode(s)
                .map(Bytes::from)
                .map_err(|e| ParseFailure::HexString("validator", e))
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
