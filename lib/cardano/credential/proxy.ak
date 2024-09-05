use aiken/collection/dict
use aiken/collection/list
use cardano/address.{Credential, Script}
use cardano/assets.{AssetName}
use cardano/transaction.{InlineDatum, Input, Output, Transaction}
use sundae/multisig.{MultisigScript}

pub type State {
  block_production_delegate: Option<MultisigScript>,
  governance_delegate: Option<MultisigScript>,
}

pub type Update {
  Register
  Unregister
}

pub type DelegateKind {
  BlockProduction
  Governance
}

pub fn delegate_kind_to_asset_name(kind: DelegateKind) -> AssetName {
  when kind is {
    BlockProduction -> "blk"
    Governance -> "gov"
  }
}

pub fn select_state(st: State, kind: DelegateKind) -> Option<MultisigScript> {
  when kind is {
    BlockProduction -> st.block_production_delegate
    Governance -> st.governance_delegate
  }
}

pub fn must_forward_script(outputs: List<Output>, from: Input) -> Bool {
  expect Some(to) =
    list.find(outputs, fn(output) { output.address == from.output.address })

  // Ensures strict following of assets.
  let from_assets = assets.without_lovelace(from.output.value)
  let to_assets = assets.without_lovelace(to.value)
  expect from_assets == to_assets

  // Ensures ADA also follows, but may increase.
  let from_lovelace = assets.lovelace_of(from.output.value)
  let to_lovelace = assets.lovelace_of(to.value)
  expect from_lovelace >= to_lovelace

  // Ensure datum is identical
  from.output.datum == to.datum
}

pub fn update_delegate(
  self: Transaction,
  redeemer: Data,
  delegate: Credential,
  kind: DelegateKind,
  update: Update,
) -> Bool {
  // Credential is necessarily a script. Note that the policy_id and
  // the _actual_ delegate representative script hash are identical
  // since they come from the same script hash.
  expect Script(policy_id) = delegate

  let asset_name = delegate_kind_to_asset_name(kind)

  let expected_quantity =
    when update is {
      Register -> {
        // When registering, we must ensure that one output targets the script.
        // This outputs is assumed to hold the minted token.
        expect Some(authorization) =
          list.find(
            self.outputs,
            fn(output) { output.address.payment_credential == delegate },
          )

        // Ensures that the output holds the token.
        expect
          assets.quantity_of(authorization.value, policy_id, asset_name) > 0

        // Ensures that the script is structurally valid, to avoid problems later.
        expect script: MultisigScript = redeemer

        // Ensures the state holds the delegate multisig script.
        expect InlineDatum(datum) = authorization.datum
        expect state: State = datum
        expect select_state(state, kind) == Some(script)

        1
      }
      // NOTE: We could also enforce that the state is reset back to 'None'
      // when de-registering. But this isn't *necessary* since the delegate
      // can only be approved if the corresponding token is present.
      Unregister -> -1
    }

  let minted_quantity =
    self.mint
      |> assets.quantity_of(policy_id, asset_name)

  // Ensure that the right amount of token is minted or burnt during the update.
  (minted_quantity == expected_quantity)?
}

pub fn must_be_approved_by_delegate(
  self: Transaction,
  delegate: Credential,
  kind: DelegateKind,
) {
  expect Script(policy_id) = delegate

  let expected_asset_name = delegate_kind_to_asset_name(kind)

  let state =
    list.foldr(
      self.inputs,
      fn() {
        fail @"no authorized delegate"
      },
      fn(input, get_state) {
        let tokens = assets.tokens(input.output.value, policy_id)
        when dict.to_pairs(tokens) is {
          [Pair(asset_name, 1)] ->
            if (asset_name == expected_asset_name)? {
              fn() {
                expect InlineDatum(state) = input.output.datum
                expect state: State = state
                state
              }
            } else {
              get_state
            }
          _ -> get_state
        }
      },
    )()

  expect Some(script) = select_state(state, kind)

  multisig.satisfied(
    script,
    self.extra_signatories,
    self.validity_range,
    self.withdrawals,
  )?
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
  )?
}
