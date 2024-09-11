use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use cardano/address.{Address, Credential, Inline, Script}
use cardano/assets.{Lovelace, PolicyId, Value, ada_policy_id}
use cardano/certificate.{
  RegisterDelegateRepresentative, UnregisterDelegateRepresentative,
}
use cardano/credential/proxy/state.{DelegateKind}
use cardano/transaction.{Input, NoDatum, Output, Transaction}
use sundae/multisig.{MultisigScript}

pub type Update {
  Register
  Unregister
}

pub fn must_forward_script(
  self: Transaction,
  from: Input,
  administrator: MultisigScript,
) -> Bool {
  let script = from.output.address.payment_credential
  expect Script(our_policy_id) = script

  // Ensures that state tokens remain trapped to a single UTxO locked by the
  // contract. Note that we must handle the case where someone is just collecting
  // other assets from the scripts as a cleanup operation. This means that we do
  // not *necessarily* have an output that targets our script.
  let our_outputs =
    list.filter(
      self.outputs,
      fn(output) { output.address.payment_credential == script },
    )

  let to =
    when our_outputs is {
      [] -> assets.zero
      [to] -> {
        // Ensure continuity of the stake credential. Even if the credential wasn't
        // set before (because some actor sent random tokens to the contract), it
        // must exist on the resulting output.
        expect to.address.stake_credential == Some(Inline(script))

        // Ensure the output is cleared of any datum or ref script. The script
        // doesn't ever use datums as it stores state in minted tokens. It's possible
        // that arbitrary actors send money to the script though, with arbitrary
        // datum/script. In which case, we simply discard them.
        expect NoDatum == to.datum
        expect None == to.reference_script

        to.value
      }
      _ -> fail @"multiple contract outputs"
    }

  // Ensure that the contract's assets follow.
  // Note that there might be more UTxOs locked at the validator address; which
  // is handled down below. Under normal use of the protocol, however, we
  // should only ever see Ada and our minting policy.
  //
  // Anything else is treated as an anomaly and must be approved by the
  // administrator. Note however that even the administrator can't take away
  // the assets from the script.
  let (from_lovelaces, from_assets, has_foreign) =
    partition_assets(self.inputs, our_policy_id)

  let authorize_special_operation =
    if assets.lovelace_of(to) < from_lovelaces || has_foreign? {
      must_be_approved_by_administrator(self, administrator)?
    } else {
      True
    }

  and {
    authorize_special_operation?,
    (assets.without_lovelace(to) == from_assets)?,
  }
}

pub fn must_forward_strict_assets(
  policy_id: PolicyId,
  from: Value,
  to: Value,
) -> Bool {
  when assets.policies(to) is {
    [p0] -> p0 == ada_policy_id
    [p0, p1] -> {
      let from_assets = assets.tokens(from, policy_id)
      let to_assets = assets.tokens(to, policy_id)
      and {
        p0 == ada_policy_id,
        p1 == policy_id,
        from_assets == to_assets,
      }
    }
    _ -> fail @"extra tokens in output"
  }
}

pub fn partition_assets(
  utxo: List<Input>,
  our_policy_id: PolicyId,
) -> (Lovelace, Value, Bool) {
  list.foldr(
    utxo,
    (0, assets.zero, False),
    fn(input, (our_lovelaces, our_assets, has_foreign)) {
      if input.output.address.payment_credential == Script(our_policy_id) {
        assets.reduce(
          input.output.value,
          (our_lovelaces, our_assets, has_foreign),
          fn(
            policy_id,
            asset_name,
            quantity,
            (our_lovelaces, our_assets, has_foreign),
          ) {
            if policy_id == ada_policy_id {
              (our_lovelaces + quantity, our_assets, has_foreign)
            } else if policy_id == our_policy_id {
              (
                our_lovelaces,
                assets.add(our_assets, policy_id, asset_name, quantity),
                has_foreign,
              )
            } else {
              (our_lovelaces, our_assets, True)
            }
          },
        )
      } else {
        (our_lovelaces, our_assets, has_foreign)
      }
    },
  )
}

pub fn update_delegate(
  self: Transaction,
  rules: Data,
  script: Credential,
  kind: DelegateKind,
  update: Update,
) -> Bool {
  // Credential is necessarily a script. Note that the policy id and
  // the actual delegate script hash are identical since they are
  // the exact same script.
  expect Script(policy_id) = script

  let mint = assets.tokens(self.mint, policy_id)

  let must_update_asset =
    when update is {
      Register -> {
        expect rules: MultisigScript = rules
        let state = state.into_asset_name(kind, rules)

        expect Some(1) = dict.get(mint, state)
        expect must_trap_tokens(policy_id, self.outputs)

        fn(asset_name, quantity) {
          // On registration we must either:
          // - Mint a new token that matches our new state
          // - Remove any previously minted token
          or {
            asset_name == state,
            quantity == -1,
          }
        }
      }

      Unregister -> {
        // NOTE: This has a side-effect of only allowing one
        // unregistration/registration per transaction, which is a fair
        // limitation.
        let is_reregistering =
          when self.certificates is {
            [UnregisterDelegateRepresentative { .. }] -> False
            [
              UnregisterDelegateRepresentative {
                delegate_representative: unregistering,
                ..
              },
              RegisterDelegateRepresentative {
                delegate_representative: registering,
                ..
              },
            ] -> registering == unregistering
            _ -> False
          }

        // On unregistration, we must simply burn tokens.
        // But, we may be re-registering in the same transaction. In which
        // case, we must allow other tokens to be minted, so we defer
        // verification to the 'Register' handler.
        if is_reregistering {
          trace @"replacing delegate"
          fn(_asset_name, _quantity) { True }
        } else {
          trace @"revoking delegate"
          // Otherwise, we simply assume it must be burnt.
          fn(_asset_name, quantity) { (quantity == -1)? }
        }
      }
    }

  // Validate every asset movement under our policy.
  dict.foldr(
    mint,
    True,
    fn(asset_name, quantity, ok) {
      if state.match_prefix(kind, asset_name) {
        ok && must_update_asset(asset_name, quantity)
      } else {
        ok
      }
    },
  )
}

// Ensures that any tokens belonging to a given policy_id (here referred to as
// 'credential') are trapped into a single output that has full control
// (payment + delegation rights) over the tokens.
pub fn must_trap_tokens(credential: ScriptHash, outputs: List<Output>) -> Bool {
  let script = Script(credential)

  // Ensure that we necessarily collapse multiple UTxO into a single output, so
  // that all minted assets are necessarily trapped in a single output. The spending
  // policy also ensures this same requirement. So while it is technically possible
  // to create multiple UTxOs by sending random assets to the assets, it is NOT
  // possible to spread the state tokens over multiple UTxOs; which is what we
  // actually care about.
  expect [to] =
    list.filter(
      outputs,
      fn(output) {
        or {
          output.address.payment_credential == script,
          assets.tokens(output.value, credential) != dict.empty,
        }
      },
    )

  // There can only be 2 policies in the trapped contract. ADA and ours.
  expect [ada_policy_id, credential] == assets.policies(to.value)

  to.address.stake_credential == Some(Inline(script))
}

pub fn must_be_approved_by_delegate(
  self: Transaction,
  rules: MultisigScript,
  delegate: Credential,
  kind: DelegateKind,
) {
  expect Script(policy_id) = delegate

  let asset_name = state.into_asset_name(kind, rules)

  // Ensure that the right rules were provided. Note that we expect them as
  // reference inputs, because the delegates cannot spend from the script.
  //
  // Since the state is kept directly as the assets which have strict minting
  // rules, it suffices to show existence of the assets to prove that an the
  // provided rules are valid for this kind and delegate.
  expect
    list.any(
      self.reference_inputs,
      fn(input) {
        assets.quantity_of(input.output.value, policy_id, asset_name) > 0
      },
    )

  // Finally, check that the rules are satisfied.
  multisig.satisfied(
    rules,
    self.extra_signatories,
    self.validity_range,
    self.withdrawals,
  )
}

pub fn must_be_approved_by_administrator(
  self: Transaction,
  administrator: MultisigScript,
) {
  multisig.satisfied(
    administrator,
    self.extra_signatories,
    self.validity_range,
    self.withdrawals,
  )
}
