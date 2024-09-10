use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use cardano/address.{Credential, Script}
use cardano/assets.{PolicyId, Value, ada_policy_id}
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

  // Ensure that we necessarily collapse multiple UTxO into a single output.
  // This prevents double-satisfaction issues down below and ensures the script
  // is kept clean. In a nominal situation, the script contains a minimal quantity
  // of ADA and up to two assets.
  expect [to] =
    list.filter(
      self.outputs,
      fn(output) { output.address.payment_credential == script },
    )

  expect [_] =
    list.filter(
      self.inputs,
      fn(input) { input.output.address.payment_credential == script },
    )

  // Ensure continuity of the stake credential.
  expect to.address == from.output.address

  // Ensure the output is cleared of any datum or ref script. The script
  // doesn't ever use datums as it stores state in minted tokens. It's possible
  // that arbitrary actors send money to the script though, with arbitrary
  // datum/script. In which case, we simply discard them.
  expect NoDatum == to.datum
  expect None == to.reference_script

  // Ensures strict following of contracts assets. We do not allow polluting
  // assets to carry over. So there must be at most two policies in the resulting
  // output: some ada that are always present, and possibly ours.
  expect Script(policy_id) = script
  expect must_forward_strict_assets(policy_id, from.output.value, to.value)

  // Ensures ADA also follows, but may increase. Unless the transaction
  // is signed by the administrator. So effectively, we allow _anyone_
  // to spend from that script provided that they strictly forward it,
  // possibly injecting money into it.
  //
  // Or, the transaction is signed by the administrator anyway who may
  // have other plans for those funds, if any. Yet, we still do not allow
  // the administrator to do anything that could be harmful to the protocol
  // (they can't take state tokens away for example).
  let from_lovelace = assets.lovelace_of(from.output.value)
  let to_lovelace = assets.lovelace_of(to.value)
  or {
    (to_lovelace >= from_lovelace)?,
    must_be_approved_by_administrator(self, administrator)?,
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

pub fn update_delegate(
  self: Transaction,
  rules: Data,
  delegate: Credential,
  kind: DelegateKind,
  update: Update,
) -> Bool {
  // Credential is necessarily a script. Note that the policy id and
  // the actual delegate script hash are identical since they are
  // the exact same script.
  expect Script(policy_id) = delegate

  let must_update_asset =
    when update is {
      Register -> {
        expect rules: MultisigScript = rules

        let state = state.into_asset_name(kind, rules)

        expect must_trap_tokens(policy_id, self.outputs)

        fn(asset_name, quantity) {
          // On registration we must either:
          // - Mint a new token that matches our new state
          // - Remove any previously minted token
          or {
            and {
              asset_name == state,
              quantity == 1,
            },
            quantity == -1,
          }
        }
      }

      Unregister ->
        fn(_asset_name, quantity) {
          // On unregistration, we must either:
          // - Burn tokens
          quantity == -1
        }
    }

  // Validate every asset movement under our policy.
  dict.foldr(
    assets.tokens(self.mint, policy_id),
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
  expect [to] =
    list.filter(
      outputs,
      fn(output) { assets.tokens(output.value, credential) != dict.empty },
    )

  let contract_address =
    address.from_script(credential)
      |> address.with_delegation_script(credential)

  to.address == contract_address
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
