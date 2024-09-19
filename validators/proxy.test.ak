//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.

use aiken/collection/dict
use aiken/collection/list.{for_each}
use aiken/collection/pairs
use aiken/crypto.{ScriptHash, VerificationKeyHash}
use aiken/fuzz.{
  and_then, bytearray_between, constant, int_at_least, int_between, label_when,
  list_between, map,
}
use aiken/fuzz/scenario.{Done, Label, Scenario}
use aiken/primitive/bytearray
use cardano/address.{Address, Script}
use cardano/assets.{
  AssetName, Lovelace, PolicyId, Value, ada_asset_name, ada_policy_id,
}
use cardano/certificate.{
  Certificate, RegisterDelegateRepresentative, UnregisterDelegateRepresentative,
}
use cardano/credential/proxy/state.{
  BlockProduction, Governance, into_asset_name, match_prefix, prefix,
}
use cardano/generator.{
  any_address, any_asset_name, any_policy_id, any_value_extending,
  any_zero_output,
}
use cardano/transaction.{
  Input, Mint, NoDatum, Output, Publish, ScriptPurpose, Spend, Transaction,
}
use cardano/transaction/script_purpose
use config
use proxy as handlers
use sundae/multisig.{MultisigScript}

const validator_hash: ScriptHash = #"0123456789abcedf"

const alice_vkh: VerificationKeyHash =
  #"000000000000000000000000000000000000000000000000000a11ce"

const bob_vkh: VerificationKeyHash =
  #"00000000000000000000000000000000000000000000000000000b0b"

const alice: MultisigScript = multisig.Signature(alice_vkh)

const bob: MultisigScript = multisig.Signature(bob_vkh)

const validator_address: Address =
  address.from_script(validator_hash)
    |> address.with_delegation_script(validator_hash)

const default_output: Output =
  Output {
    address: validator_address,
    value: assets.zero,
    datum: NoDatum,
    reference_script: None,
  }

// ------------------------------------------------------------------- state

type State {
  forwarded: Bool,
  registered: Bool,
  unregistered: Bool,
}

const default_state =
  State { forwarded: False, registered: False, unregistered: False }

// ------------------------------------------------------------------- scenarios

const sc_missing_admin_approval_for_foreign_assets: String =
  @"Missing administrator approval for foreign assets"

const sc_missing_admin_approval_for_register: String =
  @"Missing administrator approval for registration"

const sc_missing_admin_approval_for_unregister: String =
  @"Missing administrator approval for unregistration"

const sc_insufficient_lovelace_forwarded: String =
  @"Insufficient lovelace quantity forwarded"

const sc_lock_without_delegation: String =
  @"Locked without delegation credentials"

const sc_initialize_illegal_quantity: String =
  @"Initialized state token with illegal quantity"

const sc_initialize_illegal_asset_name: String =
  @"Initialized state token with illegal asset name"

const sc_no_required_initial_output: String = @"No initial output when required"

const sc_too_many_initial_outputs: String = @"Too many initial outputs"

const sc_untrapped_minted_tokens: String = @"Untrapped state tokens"

const sc_escaping_state_tokens: String = @"Escaping state tokens"

const sc_forwarded_noise: String = @"Forwarded noise assets"

const sc_too_many_forwarding_outputs: String = @"Too many forwarding outputs"

const sc_missing_certificate_with_mint: String =
  @"Missing certificates during mint/burn"

// ------------------------------------------------------------------ properties

fn cast_redeemer(
  handler: fn(MultisigScript, purpose_arg, Transaction) -> Bool,
) -> fn(Data, purpose_arg, Transaction) -> Bool {
  fn(redeemer: Data, purpose_arg, self) {
    expect rules: MultisigScript = redeemer
    handler(rules, purpose_arg, self)
  }
}

test prop_scenario_coverage(
  outcome via scenario.report_coverage(default_state, step),
) {
  label_when(outcome == scenario.Ok, @"O.K.", @"K.O.")
}

test prop_proxy_drep_ok(ok via scenario.ok(default_state, step)) {
  scenario.run(
    ok,
    validator_hash,
    handlers.direct_proxy.mint,
    handlers.direct_proxy.spend,
    handlers.direct_proxy.withdraw,
    handlers.direct_proxy.publish,
    cast_redeemer(handlers.direct_proxy.vote),
  )
}

test prop_proxy_drep_ko(
  (labels, scenario) via scenario.ko(default_state, step),
) fail {
  for_each(list.unique(labels), fuzz.label)
  scenario.run(
    scenario,
    validator_hash,
    handlers.direct_proxy.mint,
    handlers.direct_proxy.spend,
    handlers.direct_proxy.withdraw,
    handlers.direct_proxy.publish,
    cast_redeemer(handlers.direct_proxy.vote),
  )
}

// ------------------------------------------------------------- post-conditions

// ------------------------------------------------------------------ generators

// TODO: Voting
fn step(st: State, utxo: List<Input>) -> Fuzzer<Scenario<State>> {
  scenario.fork(
    if utxo == [] && !st.registered {
      // Always register
      255
    } else if !st.registered {
      // Sometimes register, with higher probability
      208
    } else {
      // No longer register
      0
    },
    fn() { register([], st, utxo) },
    fn() {
      scenario.fork(
        if st.registered && !st.unregistered {
          // Attempts to unregister
          208
        } else {
          // Only forward
          0
        },
        fn() { unregister([], st, utxo) },
        fn() {
          if !st.forwarded {
            forward_assets([], st, utxo)
          } else {
            constant(Done)
          }
        },
      )
    },
  )
}

fn register(
  labels: List<Label>,
  st: State,
  utxo: List<Input>,
) -> Fuzzer<Scenario<State>> {
  // TODO:
  // - Scenarios where we also forward gibberish
  let our_assets =
    our_value_restricted_to(utxo, [ada_policy_id, validator_hash])

  // The administrator does authorize (un)registration, and thus, it is totally
  // allowed to NOT forward all lovelaces to the resulting address. This fork
  // checks that.
  let our_assets <-
    and_then(
      scenario.fork(
        240,
        fn() { constant(our_assets) },
        fn() {
          let lovelace = assets.lovelace_of(our_assets)
          if lovelace > 1 {
            let removed <- map(int_between(1, lovelace - 1))
            assets.add(our_assets, ada_policy_id, ada_asset_name, -removed)
          } else {
            constant(our_assets)
          }
        },
      ),
    )

  let (labels, outputs) <-
    and_then(any_initial_outputs(labels, our_assets, alice))

  let (mint, mint_redeemers) = minted_tokens(outputs)

  let is_minting = mint != assets.zero

  let (labels, certs, cert_redeemers) <-
    and_then(published_certificates(labels, mint))

  let (labels, spend_redeemers) = new_spend_redeemers(labels, utxo, is_minting)

  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: utxo,
      outputs: outputs,
      mint: mint,
      certificates: certs,
      redeemers: mint_redeemers
        |> list.concat(spend_redeemers)
        |> list.concat(cert_redeemers),
    }

  let labels =
    if is_minting {
      let n_ours =
        list.count(
          outputs,
          fn(o) { o.address.payment_credential == Script(validator_hash) },
        )
      when n_ours is {
        0 -> [sc_no_required_initial_output, ..labels]
        1 -> labels
        _ -> [sc_too_many_initial_outputs, ..labels]
      }
    } else {
      list.filter(
        labels,
        fn(lbl) {
          and {
            lbl != sc_lock_without_delegation,
            lbl != sc_untrapped_minted_tokens,
          }
        },
      )
    }

  let labels =
    if utxo_holds_foreign_assets(utxo) {
      [sc_missing_admin_approval_for_foreign_assets, ..labels]
    } else {
      labels
    }

  let st = State { ..st, registered: is_minting }

  if list.is_empty(certs) {
    constant(Scenario(labels, st, tx))
  } else {
    finalize_with_signature(
      240,
      labels,
      st,
      tx,
      sc_missing_admin_approval_for_register,
    )
  }
}

fn unregister(
  labels: List<Label>,
  st: State,
  utxo: List<Input>,
) -> Fuzzer<Scenario<State>> {
  let alice_st = into_asset_name(Governance, alice)
  let bob_st = into_asset_name(Governance, bob)

  let (mint, mint_redeemers) <-
    and_then(
      scenario.fork(
        208,
        // Replace a delegate with another.
        fn() {
          constant(
            (
              assets.zero
                |> assets.add(validator_hash, alice_st, -1)
                |> assets.add(validator_hash, bob_st, 1),
              [Pair(Mint(validator_hash), void())],
            ),
          )
        },
        // Only revoke delegation
        fn() {
          constant(
            (
              assets.from_asset(validator_hash, alice_st, -1),
              [Pair(Mint(validator_hash), void())],
            ),
          )
        },
      ),
    )

  let total =
    total_value(utxo)
      |> assets.add(validator_hash, alice_st, -1)

  let (labels, certs, cert_redeemers) <-
    and_then(published_certificates(labels, mint))

  let is_registering =
    list.any(
      certs,
      fn(cert) {
        when cert is {
          RegisterDelegateRepresentative(delegate_representative, _) ->
            delegate_representative == Script(validator_hash)
          _ -> False
        }
      },
    )

  let (labels, outputs) <-
    and_then(
      if is_registering {
        let output =
          Output {
            ..default_output,
            value: assets.from_lovelace(assets.lovelace_of(total))
              |> assets.add(validator_hash, into_asset_name(Governance, bob), 1),
          }
        constant(
          if assets.quantity_of(output.value, validator_hash, bob_st) == 0 {
            ([sc_untrapped_minted_tokens, ..labels], [output])
          } else {
            (labels, [output])
          },
        )
      } else {
        let outputs <- map(any_split(total))
        (labels, outputs)
      },
    )

  // NOTE: The generation of outputs might attempts to allocate more than one
  // state token as part of a faulty scenario. We must therefore ensure that
  // this extra tokens are reflected in the mint value (enforced by phase-1
  // validations of the ledger).
  let mint =
    list.foldr(
      outputs,
      assets.add(mint, validator_hash, bob_st, -1),
      fn(output, mint) {
        assets.merge(mint, assets.restricted_to(output.value, [validator_hash]))
      },
    )

  let (labels, spend_redeemers) = new_spend_redeemers(labels, utxo, True)

  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: utxo,
      outputs: outputs,
      mint: mint,
      certificates: certs,
      redeemers: mint_redeemers
        |> list.concat(spend_redeemers)
        |> list.concat(cert_redeemers),
    }

  finalize_with_signature(
    240,
    labels,
    State { ..st, unregistered: True },
    tx,
    sc_missing_admin_approval_for_unregister,
  )
}

/// Spend a list of UTxO using (a mix of) different strategies:
///
/// - Forward all assets (including foreign ones) to a validator address
/// - Forward only lovelaces
/// - Forward a subset of the total lovelace amount
/// - Forward to a different address
/// - Single vs multi outputs
fn forward_assets(
  labels: List<String>,
  st: State,
  utxo: List<Input>,
) -> Fuzzer<Scenario<State>> {
  let st = State { ..st, forwarded: True }

  let all_value = total_value(utxo)

  let our_utxo =
    list.filter(
      utxo,
      fn(input) {
        input.output.address.payment_credential == Script(validator_hash)
      },
    )

  let our_lovelace = total_lovelace(our_utxo)

  let all_lovelace = total_lovelace(utxo)

  let (labels, outputs, forwarded_lovelace) <-
    and_then(
      scenario.fork(
        240,
        fn() {
          // Most of the time, forward all input lovelaces. Sometimes, forward less. Note that
          // this isn't an immediate K.O. scenario because it depends whether the transaction is
          // authorized by the administrators or not. So the label is applied down below, depending
          // on this fact.
          let forwarded_lovelace <-
            and_then(
              scenario.fork(
                150,
                fn() { int_between(our_lovelace, all_lovelace) },
                fn() {
                  if our_lovelace > 1 {
                    int_between(1, our_lovelace - 1)
                  } else {
                    constant(1)
                  }
                },
              ),
            )

          // Retain only the protocol assets; discard other assets.
          //
          // TODO: fork into a senario where we also forward gibberish assets.
          let our_assets =
            list.foldr(
              our_utxo,
              assets.zero,
              fn(input, our_assets) {
                dict.foldr(
                  assets.tokens(input.output.value, validator_hash),
                  our_assets,
                  fn(asset_name, quantity, our_assets) {
                    assets.add(our_assets, validator_hash, asset_name, quantity)
                  },
                )
              },
            )

          // Distribute other assets, if any, amongst one or more outputs at random.
          let outputs <-
            and_then(
              any_split(assets.merge(all_value, assets.negate(our_assets))),
            )

          // Default scenario for the contract's output. Transfer all "our assets"
          // to a single address; but insert the output at random in the outputs list.
          let single_output =
            fn() {
              let i <- and_then(int_between(0, list.length(outputs) - 1))
              constant(
                (
                  labels,
                  insert(
                    outputs,
                    i,
                    Output {
                      ..default_output,
                      value: assets.add(
                        our_assets,
                        ada_policy_id,
                        ada_asset_name,
                        forwarded_lovelace,
                      ),
                    },
                  ),
                ),
              )
            }

          // TODO: Once we support proxying for BlockProduction, fork a scenario where
          // state tokens are sent to different outputs.
          let (labels, outputs) <-
            and_then(
              // Ensure we can split the lovelace between the two outputs.
              if forwarded_lovelace <= 1 {
                single_output()
              } else {
                scenario.fork(
                  240,
                  // Forward everything to a single output
                  single_output,
                  fn() {
                    // otherwise, Split lovelaces across multiple outputs
                    let x_lovelace = forwarded_lovelace / 2
                    let y_lovelace = forwarded_lovelace - x_lovelace

                    let x_output =
                      Output {
                        ..default_output,
                        value: assets.add(
                          our_assets,
                          ada_policy_id,
                          ada_asset_name,
                          x_lovelace,
                        ),
                      }

                    let y_output =
                      Output {
                        ..default_output,
                        value: assets.from_lovelace(y_lovelace),
                      }

                    // Insert them arbitrarily in the output list
                    let len = list.length(outputs)
                    let ix <- and_then(int_between(0, len - 1))
                    let iy <- and_then(int_between(0, len))

                    constant(
                      (
                        if our_utxo == [] {
                          labels
                        } else {
                          [sc_too_many_forwarding_outputs, ..labels]
                        },
                        outputs
                          |> insert(ix, x_output)
                          |> insert(iy, y_output),
                      ),
                    )
                  },
                )
              },
            )

          expect
            !list.any(
              outputs,
              fn(o) {
                o.address.payment_credential == Script(validator_hash) && value_holds_foreign_assets(
                  o.value,
                )
              },
            )

          constant((labels, outputs, forwarded_lovelace))
        },
        fn() {
          // Otherwise, distribute all assets at random which should
          // be caught and rejected by the spend validator.
          let outputs <- map(any_split(all_value))
          if assets.tokens(all_value, validator_hash) != dict.empty {
            ([sc_escaping_state_tokens, ..labels], outputs, 0)
          } else {
            (labels, outputs, 0)
          }
        },
      ),
    )

  expect outputs != []

  let (labels, spend_redeemers) = new_spend_redeemers(labels, utxo, False)

  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: utxo,
      outputs: outputs,
      redeemers: spend_redeemers,
    }

  // NOTE: A signature from the administrator might be needed in two cases:
  //
  // - We are trying to spend assets that do long belong to the validator
  // - We are trying to re-allocate some lovelace quantity
  //
  // So we do sign conditionally, but we distinguish the two failing scenarios
  // to generate better errors/reporting.
  if utxo_holds_foreign_assets(our_utxo) {
    finalize_with_signature(
      128,
      labels,
      st,
      tx,
      sc_missing_admin_approval_for_foreign_assets,
    )
  } else if our_lovelace > 0 && forwarded_lovelace < our_lovelace {
    finalize_with_signature(
      220,
      labels,
      st,
      tx,
      sc_insufficient_lovelace_forwarded,
    )
  } else {
    // NOTE: This else branch is *not necessarily* O.K. as it depends on
    // the way we constructed the output which is captured within the 'labels'
    constant(Scenario(labels, st, tx))
  }
}

/// Generate a random distribution of outputs given a total value.
fn any_split(total: Value) -> Fuzzer<List<Output>> {
  let outputs <- and_then(list_between(any_zero_output(), 1, 3))
  assets.reduce(
    total,
    constant(
      list.map(outputs, fn(self) { Output { ..self, value: assets.zero } }),
    ),
    fn(policy_id, asset_name, quantity, generator) {
      let outputs <- and_then(generator)
      distribute(policy_id, asset_name, quantity, outputs)
    },
  )
}

/// Generate some initial outputs, which may target the validator address,
/// and that may or may not contains assets.
fn any_initial_outputs(
  labels: List<Label>,
  in: Value,
  rules: MultisigScript,
) -> Fuzzer<(List<Label>, List<Output>)> {
  scenario.fork2(
    230,
    fn() {
      // Generate a single initial output
      let (labels, output) <- map(any_initial_output(labels, in, rules))
      (labels, [output])
    },
    // Generate 0 initial outputs
    fn() {
      if assets.lovelace_of(in) > 0 {
        constant(([sc_insufficient_lovelace_forwarded, ..labels], []))
      } else {
        constant((labels, []))
      }
    },
    fn() {
      // Generate many (>= 2) initial outputs.
      let (fst_labels, fst_output) <-
        and_then(any_initial_output(labels, in, rules))
      let (snd_labels, snd_output) <-
        map(any_initial_output(labels, assets.zero, rules))
      (list.concat(fst_labels, snd_labels), [fst_output, snd_output])
    },
  )
}

fn any_initial_output(
  labels: List<Label>,
  in: Value,
  rules: MultisigScript,
) -> Fuzzer<(List<Label>, Output)> {
  let (labels, value) <- and_then(any_initial_value(labels, in, rules))

  let (labels, address) <-
    map(
      scenario.fork2(
        230,
        fn() { constant((labels, validator_address)) },
        fn() {
          constant(
            (
              [sc_lock_without_delegation, ..labels],
              address.from_script(validator_hash),
            ),
          )
        },
        fn() {
          let addr <- map(any_address())
          if assets.tokens(value, validator_hash) != dict.empty {
            ([sc_untrapped_minted_tokens, ..labels], addr)
          } else {
            (labels, addr)
          }
        },
      ),
    )

  let labels =
    if address.payment_credential == Script(validator_hash) && value_holds_foreign_assets(
      value,
    ) {
      [sc_forwarded_noise, ..labels]
    } else {
      labels
    }

  (labels, Output { ..default_output, value: value, address: address })
}

fn any_initial_value(
  labels: List<Label>,
  in: Value,
  rules: MultisigScript,
) -> Fuzzer<(List<Label>, Value)> {
  scenario.fork3(
    230,
    // Generate an initial output with a valid state token.
    fn() {
      scenario.fork(
        245,
        // Only ADA & the state token, as it should be.
        fn() {
          let lovelace <- map(int_at_least(1))
          (
            labels,
            in
              |> assets.add(ada_policy_id, ada_asset_name, lovelace)
              |> assets.add(validator_hash, into_asset_name(Governance, rules), 1),
          )
        },
        // or with noise assets around.
        fn() {
          let policy_id <- and_then(any_policy_id())
          let asset_name <- and_then(any_asset_name())
          let quantity <- map(int_at_least(1))
          let value = assets.add(in, policy_id, asset_name, quantity)
          (
            [sc_forwarded_noise, ..labels],
            assets.add(
              value,
              validator_hash,
              into_asset_name(Governance, rules),
              1,
            ),
          )
        },
      )
    },
    fn() {
      let value <- and_then(any_value_extending(in))
      let quantity <- map(int_between(2, 5))
      (
        [sc_initialize_illegal_quantity, ..labels],
        assets.add(
          value,
          validator_hash,
          into_asset_name(Governance, rules),
          quantity,
        ),
      )
    },
    fn() {
      let value <- and_then(any_value_extending(in))
      let gibberish <- map(bytearray_between(0, 8))
      let asset_name = bytearray.concat(prefix(Governance), gibberish)
      (
        [sc_initialize_illegal_asset_name, ..labels],
        assets.add(value, validator_hash, asset_name, 1),
      )
    },
    fn() {
      let value <- map(any_value_extending(in))
      (labels, value)
    },
  )
}

/// Distributes an asset quantity across a list of outputs. Fails if the given
/// list is empty; retuns a list of the same size.
fn distribute(
  policy_id: PolicyId,
  asset_name: AssetName,
  quantity: Int,
  outputs: List<Output>,
) -> Fuzzer<List<Output>> {
  if quantity <= 0 {
    constant(outputs)
  } else {
    when outputs is {
      [] -> fail @"cannot distribute to empty outputs"
      [head] ->
        constant(
          [
            Output {
              ..head,
              value: assets.add(head.value, policy_id, asset_name, quantity),
            },
          ],
        )
      [head, ..tail] ->
        scenario.fork2(
          85,
          // Forward everything to the first output.
          fn() {
            constant(
              [
                Output {
                  ..head,
                  value: assets.add(head.value, policy_id, asset_name, quantity),
                },
                ..tail
              ],
            )
          },
          fn() {
            // Forward a fraction to the first output
            let n <- and_then(int_between(1, quantity))
            let head =
              Output {
                ..head,
                value: assets.add(head.value, policy_id, asset_name, n),
              }
            distribute(policy_id, asset_name, quantity - n, [head, ..tail])
          },
          fn() {
            // Skip this output entirely
            let tail <-
              and_then(distribute(policy_id, asset_name, quantity, tail))
            constant([head, ..tail])
          },
        )
    }
  }
}

fn finalize_with_signature(
  pivot: Int,
  labels: List<Label>,
  st: State,
  tx: Transaction,
  on_missing_signature: String,
) -> Fuzzer<Scenario<State>> {
  scenario.fork(
    pivot,
    fn() {
      let labels =
        list.filter(
          labels,
          fn(lbl) {
            and {
              lbl != sc_insufficient_lovelace_forwarded,
              lbl != sc_missing_admin_approval_for_foreign_assets,
              lbl != sc_missing_admin_approval_for_register,
              lbl != sc_missing_admin_approval_for_unregister,
            }
          },
        )
      constant(
        Scenario(
          labels,
          st,
          Transaction { ..tx, extra_signatories: config.administrators },
        ),
      )
    },
    fn() { constant(Scenario([on_missing_signature, ..labels], st, tx)) },
  )
}

// ------------------------------------------------------------------- redeemers

fn void() -> Data {
  let data: Data = Void
  data
}

/// Construct 'Spend' redeemers for a given UTxO set; only cares about those locked
/// by our validator.
fn new_spend_redeemers(
  labels: List<Label>,
  utxo: List<Input>,
  is_minting: Bool,
) -> (List<Label>, Pairs<ScriptPurpose, Data>) {
  let redeemers =
    list.filter_map(
      utxo,
      fn(input) {
        if input.output.address.payment_credential == Script(validator_hash) {
          Some(Pair(Spend(input.output_reference), void()))
        } else {
          None
        }
      },
    )

  let labels =
    if redeemers == [] && !is_minting {
      list.filter(labels, fn(lbl) { lbl != sc_forwarded_noise })
    } else {
      labels
    }

  (labels, redeemers)
}

/// Extract minted token value from an initial list of output. Note that this
/// somehow mimicks the ledger's behaviour as we cannot create arbitrary tokens
/// without minting them.
///
/// NOTE: We do not fork scenarios where we try to mint illegal quantities because
/// this is already handled by the scenario *sc_initialize_illegal_quantity* which
/// is reflected in the `outputs` received as parameters here.
///
/// Plus, the ledger itself ensures that tokens cannot disappear or appear out of
/// thin air. So, if an illegal quantity is found in an initial output, then it is
/// necessarily reflected as minting/burning quantity.
fn minted_tokens(outputs: List<Output>) -> (Value, Pairs<ScriptPurpose, Data>) {
  let mint =
    list.foldr(
      outputs,
      assets.zero,
      fn(output, mint) {
        assets.reduce(
          output.value,
          mint,
          fn(policy_id, asset_name, quantity, mint) {
            if policy_id == validator_hash {
              assets.add(mint, policy_id, asset_name, quantity)
            } else {
              mint
            }
          },
        )
      },
    )

  (
    mint,
    list.foldr(
      assets.policies(mint),
      [],
      fn(policy_id, redeemers) {
        pairs.insert_by_ascending_key(
          redeemers,
          Mint(policy_id),
          void(),
          script_purpose.compare,
        )
      },
    ),
  )
}

fn published_certificates(
  labels: List<Label>,
  mint: Value,
) -> Fuzzer<(List<Label>, List<Certificate>, Pairs<ScriptPurpose, Data>)> {
  let tokens = assets.tokens(mint, validator_hash)
  if tokens != dict.empty {
    let indexed_certificates =
      dict.foldr(
        tokens,
        (dict.size(tokens) - 1, []),
        fn(token, quantity, (ix, certificates)) {
          if match_prefix(Governance, token) && quantity > 0 {
            let rules: Data =
              if into_asset_name(Governance, alice) == token {
                alice
              } else {
                bob
              }
            let register_drep =
              RegisterDelegateRepresentative {
                delegate_representative: Script(validator_hash),
                deposit: 0,
              }
            (ix - 1, [(ix, rules, register_drep), ..certificates])
          } else if match_prefix(Governance, token) && quantity < 0 {
            let unregister_drep =
              UnregisterDelegateRepresentative {
                delegate_representative: Script(validator_hash),
                refund: 0,
              }
            (ix - 1, [(ix, void(), unregister_drep), ..certificates])
          } else {
            (ix - 1, certificates)
          }
        },
      ).2nd

    if indexed_certificates == [] {
      constant((labels, [], []))
    } else {
      scenario.fork(
        245,
        fn() {
          constant(
            list.foldr(
              indexed_certificates,
              (labels, [], []),
              fn((ix, rules, cert), (labels, certificates, redeemers)) {
                (
                  labels,
                  [cert, ..certificates],
                  pairs.insert_by_ascending_key(
                    redeemers,
                    Publish(ix, cert),
                    rules,
                    script_purpose.compare,
                  ),
                )
              },
            ),
          )
        },
        fn() {
          constant(([sc_missing_certificate_with_mint, ..labels], [], []))
        },
      )
    }
  } else {
    constant((labels, [], []))
  }
}

// --------------------------------------------------------------------- helpers

fn utxo_holds_foreign_assets(utxo: List<Input>) -> Bool {
  list.any(
    utxo,
    fn(input) {
      and {
        input.output.address.payment_credential == Script(validator_hash),
        value_holds_foreign_assets(input.output.value),
      }
    },
  )
}

fn value_holds_foreign_assets(value: Value) -> Bool {
  list.any(
    assets.flatten(value),
    fn((policy_id, asset_name, _)) {
      if policy_id == assets.ada_policy_id {
        False
      } else {
        or {
          policy_id != validator_hash,
          and {
            !match_prefix(BlockProduction, asset_name),
            !match_prefix(Governance, asset_name),
          },
        }
      }
    },
  )
}

// TODO: Move to stdlib

fn total_lovelace(utxo: List<Input>) -> Lovelace {
  list.foldr(
    utxo,
    0,
    fn(input, total) { total + assets.lovelace_of(input.output.value) },
  )
}

fn total_value(utxo: List<Input>) -> Value {
  list.foldr(
    utxo,
    assets.zero,
    fn(input, value) { assets.merge(value, input.output.value) },
  )
}

fn our_value_restricted_to(utxo: List<Input>, mask: List<PolicyId>) -> Value {
  list.foldr(
    utxo,
    assets.zero,
    fn(input, our_assets) {
      if input.output.address.payment_credential == Script(validator_hash) {
        let restricted = assets.restricted_to(input.output.value, mask)
        assets.merge(our_assets, restricted)
      } else {
        our_assets
      }
    },
  )
}

/// Insert an element in a list at the given position.
fn insert(self: List<a>, ix: Int, elem: a) -> List<a> {
  when self is {
    [] -> [elem]
    [head, ..tail] ->
      if ix == 0 {
        [elem, head, ..tail]
      } else {
        [head, ..insert(tail, ix - 1, elem)]
      }
  }
}
