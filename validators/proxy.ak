use aiken/collection/dict
use aiken/collection/list
use cardano/address.{Credential, Script}
use cardano/assets.{PolicyId}
use cardano/certificate.{
  Certificate, DelegateCredential, RegisterAndDelegateCredential,
  RegisterCredential, RegisterDelegateRepresentative, UnregisterCredential,
  UnregisterDelegateRepresentative, UpdateDelegateRepresentative,
}
use cardano/credential/proxy.{
  BlockProduction, Governance, must_be_approved_by_administrator,
  must_be_approved_by_delegate, must_forward_script, update_delegate,
}
use cardano/governance.{DelegateRepresentative, Voter}
use cardano/transaction.{Input, OutputReference, Transaction}
use config
use sundae/multisig.{MultisigScript}

const administrator: MultisigScript =
  multisig.AtLeast {
    required: config.threshold,
    scripts: list.map(config.administrators, multisig.Signature),
  }

validator direct_proxy {
  // The minting and burning of tokens is mostly delegated and tied to the registration/unregistration of
  // the delegate script credential. The ledger enforces that one can only register a DRep once, which gives
  // us the uniqueness property necessary to issue an NFT.
  //
  // We fully bind the token's life to the delegate representative and thus, it must also be deleted when
  // upon de-registering the delegate. Hence, the presence of a matching `RegisterDelegateRepresentative` or
  // `UnregisterDelegateRepresentative` implies the execution of the `purpose` handler.
  mint(_redeemer: Void, policy_id: PolicyId, self: Transaction) {
    list.any(
      self.certificates,
      fn(certificate) {
        when certificate is {
          RegisterDelegateRepresentative {
            delegate_representative: credential,
            ..
          } | UnregisterDelegateRepresentative {
            delegate_representative: credential,
            ..
          } | RegisterCredential { credential, .. } | UnregisterCredential {
            credential,
            ..
          } | RegisterAndDelegateCredential { credential, .. } ->
            credential == Script(policy_id)
          _ -> False
        }
      },
    )
  }

  // The script is mostly just a vault; it isn't meant to manage anything other
  // than the state of the account and of the contract. We ensure however that
  // the proof tokens cannot ever leave the script unless it's meant by the
  // proxy script (i.e. token is burnt).
  spend(
    _datum: Option<Data>,
    _redeemer: Data<Void>,
    utxo: OutputReference,
    self: Transaction,
  ) {
    expect Some(from) =
      list.find(self.inputs, fn(input) { input.output_reference == utxo })

    or {
      // If there's no mint or burn, we allow forwarding the script to a
      // continuing output. This can only ever add Ada to the script.
      and {
        (self.mint == assets.zero)?,
        must_forward_script(self.outputs, from),
      },
      // Otherwise, we must necessarily be minting/burning one of the state
      // token. So it suffices to ensure that the minting handler is being
      // executed.
      {
        expect Script(policy_id) = from.output.address.payment_credential
        assets.tokens(self.mint, policy_id) != dict.empty
      },
    }
  }

  // Withdrawal of rewards are simply delegated to the hot block production delegate.
  withdraw(_redeemer: Data<Void>, account: Credential, self: Transaction) {
    or {
      must_be_approved_by_administrator(self, administrator),
      must_be_approved_by_delegate(self, account, BlockProduction),
    }
  }

  publish(
    redeemer: Data<MultisigScript>,
    certificate: Certificate,
    self: Transaction,
  ) {
    when certificate is {
      // The registration (resp. unregistration) of delegate credential for
      // block production is the responsibility of the administrator  . As a
      // proof of it happening properly, we issue (resp. burn) a token that is
      // fully managed by the proxy script.
      RegisterCredential { credential, .. } | RegisterAndDelegateCredential {
        credential,
        ..
      } -> and {
          must_be_approved_by_administrator(self, administrator),
          update_delegate(
            self,
            redeemer,
            credential,
            BlockProduction,
            proxy.Register,
          ),
        }
      UnregisterCredential { credential, .. } -> and {
          must_be_approved_by_administrator(self, administrator),
          update_delegate(
            self,
            redeemer,
            credential,
            BlockProduction,
            proxy.Unregister,
          ),
        }

      // The 'DelegateCredential' is the actual action that's being off-loaded
      // to the `block_production_delegate`.
      DelegateCredential { credential, .. } ->
        must_be_approved_by_delegate(self, credential, BlockProduction)

      // The registration (resp. unregistration) of delegate credential for
      // governance is the responsibility of the administrator  . As a proof of
      // it happening properly, we issue (resp. burn) a token that is fully
      // managed by the proxy script.
      RegisterDelegateRepresentative { delegate_representative: delegate, .. } ->
        and {
          must_be_approved_by_administrator(self, administrator),
          update_delegate(self, redeemer, delegate, Governance, proxy.Register),
        }
      UnregisterDelegateRepresentative { delegate_representative: delegate, .. } ->
        and {
          must_be_approved_by_administrator(self, administrator),
          update_delegate(
            self,
            redeemer,
            delegate,
            Governance,
            proxy.Unregister,
          ),
        }

      // The UpdateDelegateRepresentative certificate is only used to update
      // metadata associated with the delegate. It is reasonable to grant this
      // responsibility to the governance delegate.
      UpdateDelegateRepresentative { delegate_representative: delegate } ->
        must_be_approved_by_delegate(self, delegate, Governance)

      // Stake pool related certificates are just considered invalid here.
      _ -> fail
    }
  }

  vote(_redeemer: Data<Void>, voter: Voter, self: Transaction) {
    expect DelegateRepresentative(delegate) = voter
    must_be_approved_by_delegate(self, delegate, Governance)
  }

  propose(_redeemer, _proposal, _self) {
    fail
  }
}
