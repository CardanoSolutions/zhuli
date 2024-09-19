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
    match cmd::cli().get_matches().subcommand() {
        Some(("vote", args)) => {
            let network = Cardano::new();

            let delegates = cmd::get_arg_delegates(args)?;
            let choice = cmd::get_arg_vote(args);
            let anchor = cmd::get_arg_anchor(args).await;
            let proposal = cmd::get_arg_proposal(args)?;
            let contract = cmd::get_arg_contract(args)?.unwrap();
            let fuel = cmd::get_arg_fuel(args)?;

            report(cmd::vote(network, delegates, choice, anchor, proposal, contract, fuel).await)
        }

        Some(("delegate", args)) => {
            let network = Cardano::new();

            let contract = cmd::get_arg_contract(args)?;
            let administrators = cmd::get_arg_administrators(args)?;
            let delegates = cmd::get_arg_delegates(args)?;
            let quorum = cmd::get_arg_quorum(args)?.unwrap_or(delegates.len());
            let fuel = cmd::get_arg_fuel(args)?;

            report(if let Some(contract) = contract {
                cmd::redelegate(network, delegates, quorum, administrators, contract, fuel).await
            } else {
                let validator = cmd::get_arg_validator(args)?.unwrap();
                cmd::delegate(network, delegates, quorum, administrators, validator, fuel).await
            })
        }

        Some(("revoke", args)) => {
            let network = Cardano::new();

            let contract = cmd::get_arg_contract(args)?.unwrap();
            let fuel = cmd::get_arg_fuel(args)?;
            let administrators = cmd::get_arg_administrators(args)?;
            report(cmd::revoke(network, administrators, contract, fuel).await)
        }

        _ => unreachable!(),
    }
}

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
