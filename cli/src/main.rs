use cardano::Cardano;
use indoc::printdoc;
use pallas_codec::minicbor as cbor;
use pallas_primitives::conway::Tx;

mod cardano;
mod cmd;
mod contract;
mod pallas_extra;

#[tokio::main]
async fn main() -> Result<(), cmd::ParseFailure> {
    let network = Cardano::new();

    match cmd::cli().get_matches().subcommand() {
        Some(("delegate", args)) => {
            let contract = cmd::get_arg_contract(args)?;
            let administrators = cmd::get_arg_administrators(args)?;
            let delegates = cmd::get_arg_delegates(args)?;
            let quorum = cmd::get_arg_quorum(args)?.unwrap_or(delegates.len());
            let fuel = cmd::get_arg_fuel(args)?;

            report(if let Some(contract) = contract {
                cmd::redelegate(network, administrators, delegates, quorum, contract, fuel).await
            } else {
                let validator = cmd::get_arg_validator(args)?.unwrap();
                cmd::delegate(network, validator, administrators, delegates, quorum, fuel).await
            })
        }

        Some(("vote", args)) => {
            let delegates = cmd::get_arg_delegates(args)?;
            let choice = cmd::get_arg_vote(args);
            let anchor = cmd::get_arg_anchor(args).await;
            let proposal = cmd::get_arg_proposal(args)?;
            let contract = cmd::get_arg_contract(args)?.unwrap();
            let fuel = cmd::get_arg_fuel(args)?;

            report(cmd::vote(network, delegates, choice, anchor, proposal, contract, fuel).await)
        }

        Some(("revoke", _)) => report(cmd::revoke(network).await),

        _ => unreachable!(),
    }
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
