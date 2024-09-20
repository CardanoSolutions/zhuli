////  This Source Code Form is subject to the terms of the Mozilla Public
////  License, v. 2.0. If a copy of the MPL was not distributed with this
////  file, You can obtain one at http://mozilla.org/MPL/2.0/.

use aiken/collection/dict
use aiken/collection/list
use cardano/address.{Credential, Script}
use cardano/assets.{PolicyId}
use cardano/certificate.{
  Certificate, RegisterDelegateRepresentative, UnregisterDelegateRepresentative,
  UpdateDelegateRepresentative,
}
use cardano/governance.{DelegateRepresentative, Voter}
use cardano/transaction.{Input, OutputReference, Transaction}
use config
use sundae/multisig.{MultisigScript}
use zhuli/predicate.{
  Register, Unregister, must_be_approved_by_administrator,
  must_be_approved_by_delegate, must_forward_script, update_delegate,
}
use zhuli/state.{Governance}

const administrator: MultisigScript =
  multisig.AtLeast {
    required: config.quorum,
    scripts: list.map(config.administrators, multisig.Signature),
  }

validator zhuli {
  // The minting and burning of tokens is mostly delegated and tied to the registration/unregistration of
  // the delegate script credential. The ledger enforces that one can only register a DRep once, which gives
  // us the uniqueness property necessary to issue an NFT.
  //
  // We fully bind the token's life to the delegate representative and thus, it must also be deleted when
  // upon de-registering the delegate. Hence, the presence of a matching `RegisterDelegateRepresentative` or
  // `UnregisterDelegateRepresentative` implies the execution of the `purpose` handler.
  mint(_redeemer: Data, policy_id: PolicyId, self: Transaction) {
    let must_publish_certificates =
      list.any(
        self.certificates,
        fn(certificate) {
          when certificate is {
            RegisterDelegateRepresentative {
              delegate_representative: credential,
              ..
            } |
            UnregisterDelegateRepresentative {
              delegate_representative: credential,
              ..
            } -> (credential == Script(policy_id))?
            _ -> False
          }
        },
      )
    must_publish_certificates?
  }

  // The script is only useful as a stake credential. But it is also a trap for
  // the state tokens that are minted / burned for the delegates.
  // Yet, it is also possible for arbitrary users to send money to the account.
  spend(
    _datum: Option<Data>,
    _redeemer: Data<Void>,
    utxo: OutputReference,
    self: Transaction,
  ) {
    expect Some(from) =
      list.find(self.inputs, fn(input) { input.output_reference == utxo })

    if (self.mint == assets.zero)? {
      // If there's no mint or burn, we allow forwarding the script to a
      // continuing output. This can only ever add Ada to the script.
      must_forward_script(self, from, administrator)?
    } else {
      // Otherwise, we must necessarily be minting/burning one of the state
      // token. So it suffices to ensure that the minting handler is being
      // executed.
      expect Script(policy_id) = from.output.address.payment_credential
      let must_mint_or_burn_tokens =
        assets.tokens(self.mint, policy_id) != dict.empty
      must_mint_or_burn_tokens?
    }
  }

  // Withdrawal of rewards must be approved by the delegate
  withdraw(
    redeemer: Data<MultisigScript>,
    account: Credential,
    self: Transaction,
  ) {
    or {
      must_be_approved_by_administrator(self, administrator)?,
      {
        expect rules: MultisigScript = redeemer
        must_be_approved_by_delegate(self, rules, account, Governance)?
      },
    }
  }

  publish(
    rules: Data<MultisigScript>,
    certificate: Certificate,
    self: Transaction,
  ) {
    when certificate is {
      // The registration (resp. unregistration) of delegate credential for
      // governance is the responsibility of the administrator  . As a proof of
      // it happening properly, we issue (resp. burn) a token that is fully
      // managed by the proxy script.
      RegisterDelegateRepresentative { delegate_representative: delegate, .. } ->
        and {
          must_be_approved_by_administrator(self, administrator)?,
          update_delegate(self, rules, delegate, Governance, Register)?,
        }

      UnregisterDelegateRepresentative { delegate_representative: delegate, .. } ->
        and {
          must_be_approved_by_administrator(self, administrator)?,
          update_delegate(self, rules, delegate, Governance, Unregister)?,
        }

      // The UpdateDelegateRepresentative certificate is only used to update
      // metadata associated with the delegate. It is reasonable to grant this
      // responsibility to the governance delegate.
      UpdateDelegateRepresentative { delegate_representative: delegate } -> {
        expect rules: MultisigScript = rules
        must_be_approved_by_delegate(self, rules, delegate, Governance)?
      }

      // Stake pool related certificates are just considered invalid here.
      _ -> must_be_approved_by_administrator(self, administrator)?
    }
  }

  vote(rules: MultisigScript, voter: Voter, self: Transaction) {
    expect DelegateRepresentative(delegate) = voter
    must_be_approved_by_delegate(self, rules, delegate, Governance)
  }

  propose(_redeemer, _proposal, _self) {
    fail
  }
}
