use aiken/collection.{Index}
use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken/fuzz.{
  and_then, both, bytearray_between, constant, either, int, int_at_least,
  int_between, label, map, option, set_between, such_that,
}
use aiken/primitive/bytearray
use aiken/primitive/int
use aiken/primitive/string
use cardano/address.{Address, Inline, Script, VerificationKey}
use cardano/assets.{AssetName, PolicyId, Value}
use cardano/credential/proxy.{must_forward_script, must_forward_strict_assets}
use cardano/transaction.{
  Datum, DatumHash, InlineDatum, Input, NoDatum, Output, OutputReference,
  Transaction,
}
use sundae/multisig.{MultisigScript}

// NOTE: Needs not to be an actual policy id, as we never re-hash anything. So
// we might as well make it something we can easily recognize.
const proxy: ScriptHash = "proxy"

const proxy_address: Address =
  address.from_script(proxy) |> address.with_delegation_script(proxy)

// NOTE: Similarly, we need not the administrator script to be anything complex,
// nor to be a valid key hash.
const administrator: MultisigScript = multisig.Signature("administrator")

// -----------------------------------------------------------------------------
// ------------------------------------------------------- must_forward_script -
// -----------------------------------------------------------------------------

type Position {
  Front
  Back
}

fn gen_position() -> Fuzzer<Position> {
  either(constant(Front), constant(Back))
}

fn position_to_string(self: Position) -> String {
  when self is {
    Front -> @"front"
    Back -> @"back"
  }
}

type Mutation {
  AddInput(Position, OutputOrigin, Input)
  ReplaceInput(Index, OutputOrigin, Input)
  RemoveInput(Index)
  AddOutput(Position, OutputOrigin, Output)
}

type OutputOrigin {
  Arbitrary
  Derived(OutputDerivation)
}

type OutputDerivation {
  /// Complete clone, everything is identical
  Clone
  /// Same output address, everything else is arbitrary.
  SameAddress
  /// Same output datum, everything else is arbitrary
  SameDatum
}

fn output_origin_to_string(self: OutputOrigin) -> String {
  when self is {
    Arbitrary -> @"arbitrary output"
    Derived(Clone) -> @"similar output (clone)"
    Derived(SameAddress) -> @"similar output (same address)"
    Derived(SameDatum) -> @"similar output (same datum)"
  }
}

fn gen_mutation(
  self: Transaction,
  satisfies: fn(Mutation) -> Bool,
) -> Fuzzer<Mutation> {
  {
    let variant <- and_then(int_between(0, 100))
    if variant >= 95 {
      gen_remove_input(self)
    } else {
      when variant % 3 is {
        0 -> gen_add_input(self)
        1 -> gen_replace_input(self)
        _ -> gen_add_output(self)
      }
    }
  }
    |> such_that(satisfies)
}

fn gen_remove_input(self: Transaction) -> Fuzzer<Mutation> {
  let at <- map(int_between(0, list.length(self.inputs) - 1))
  RemoveInput(at)
}

fn gen_replace_input(self: Transaction) -> Fuzzer<Mutation> {
  let variant <- and_then(int_between(0, 3))
  when variant is {
    0 -> {
      let at <- and_then(int_between(0, list.length(self.inputs) - 1))
      let input <- map(gen_input())
      ReplaceInput(at, Arbitrary, input)
    }

    1 -> {
      let (at, input) <- and_then(pick(self.inputs))
      let output_index <- map(int_at_least(0))
      let input =
        Input {
          output_reference: OutputReference {
            ..input.output_reference,
            output_index: output_index,
          },
          output: input.output,
        }
      ReplaceInput(at, Derived(Clone), input)
    }

    2 -> {
      let (at, Input { output: Output { address, .. }, .. }) <-
        and_then(pick(self.inputs))
      let input <- map(gen_input())
      let input =
        Input { ..input, output: Output { ..input.output, address: address } }
      ReplaceInput(at, Derived(SameAddress), input)
    }

    3 -> {
      let (at, Input { output: Output { datum, .. }, .. }) <-
        and_then(pick(self.inputs))
      let input <- map(gen_input())
      let input =
        Input { ..input, output: Output { ..input.output, datum: datum } }
      ReplaceInput(at, Derived(SameDatum), input)
    }

    _ -> fail @"unexpected ReplaceInput variant index"
  }
}

fn gen_add_output(self: Transaction) -> Fuzzer<Mutation> {
  let variant <- and_then(int_between(0, 3))

  when variant is {
    0 -> {
      let position <- and_then(gen_position())
      let output <- map(gen_output())
      AddOutput(position, Arbitrary, output)
    }

    1 -> {
      let (_, output) <- and_then(pick(self.outputs))
      let position <- map(gen_position())
      AddOutput(position, Derived(Clone), output)
    }

    2 -> {
      let (_, Output { address, .. }) <- and_then(pick(self.outputs))
      let position <- and_then(gen_position())
      let output <- map(gen_output())
      let output = Output { ..output, address: address }
      AddOutput(position, Derived(SameAddress), output)
    }

    3 -> {
      let (_, Output { datum, .. }) <- and_then(pick(self.outputs))
      let position <- and_then(gen_position())
      let output <- map(gen_output())
      let output = Output { ..output, datum: datum }
      AddOutput(position, Derived(SameDatum), output)
    }

    _ -> fail @"unexpected AddOutput variant index"
  }
}

fn gen_add_input(self: Transaction) -> Fuzzer<Mutation> {
  let variant <- and_then(int_between(0, 3))
  when variant is {
    0 -> {
      let position <- and_then(gen_position())
      let input <- map(gen_input())
      AddInput(position, Arbitrary, input)
    }

    1 -> {
      let (_, input) <- and_then(pick(self.inputs))
      let position <-
        map(
          if input.output_reference.output_index == 0 {
            constant(Back)
          } else {
            gen_position()
          },
        )
      let input =
        Input {
          output_reference: OutputReference {
            ..input.output_reference,
            output_index: input.output_reference.output_index + when
              position
            is {
              Back -> 1
              Front -> -1
            },
          },
          output: input.output,
        }
      AddInput(position, Derived(Clone), input)
    }

    2 -> {
      let (_, input) <- and_then(pick(self.inputs))
      let address = input.output.address
      let position <- and_then(gen_position())
      let input <- map(gen_input_at(position, self))
      let input =
        Input {
          output_reference: input.output_reference,
          output: Output { ..input.output, address: address },
        }
      AddInput(position, Derived(SameAddress), input)
    }

    3 -> {
      let (_, input) <- and_then(pick(self.inputs))
      let datum = input.output.datum
      let position <- and_then(gen_position())
      let input <- map(gen_input_at(position, self))
      let input =
        Input {
          output_reference: input.output_reference,
          output: Output { ..input.output, datum: datum },
        }
      AddInput(position, Derived(SameDatum), input)
    }

    _ -> fail @"unexpected AddInput variant index"
  }
}

fn compare_input(left: Input, right: Input) -> Ordering {
  let left = left.output_reference
  let right = right.output_reference
  when bytearray.compare(left.transaction_id, right.transaction_id) is {
    Equal -> int.compare(left.output_index, right.output_index)
    ordering -> ordering
  }
}

fn mutation_to_label(mutation: Mutation) -> String {
  when mutation is {
    AddInput(position, origin, ..) ->
      string.join(
        [
          @"Add input with",
          output_origin_to_string(origin),
          @"to",
          position_to_string(position),
        ],
        @" ",
      )
    ReplaceInput(ix, origin, ..) ->
      string.join(
        [
          @"Replace input with",
          output_origin_to_string(origin),
          @"at position",
          int.to_string(ix),
        ],
        @" ",
      )
    RemoveInput(ix) ->
      string.join([@"Remove input at position", int.to_string(ix)], @" ")
    AddOutput(position, origin, ..) ->
      string.join(
        [
          @"Add",
          output_origin_to_string(origin),
          @"to",
          position_to_string(position),
        ],
        @" ",
      )
  }
}

fn apply_mutation(self: Transaction, mutation: Mutation) -> Transaction {
  when mutation is {
    AddInput(position, _, input) ->
      Transaction {
        ..self,
        inputs: when position is {
          Front ->
            [input, ..self.inputs]
          Back -> list.foldr(self.inputs, [input], fn(x, xs) { [x, ..xs] })
        },
      }
    AddOutput(position, _, output) ->
      Transaction {
        ..self,
        outputs: when position is {
          Front ->
            [output, ..self.outputs]
          Back -> list.foldr(self.outputs, [output], fn(x, xs) { [x, ..xs] })
        },
      }
    ReplaceInput(i, _, input) ->
      Transaction {
        ..self,
        inputs: list.indexed_foldr(
          self.inputs,
          [],
          fn(j, x, xs) {
            if i == j {
              [input, ..xs]
            } else {
              [x, ..xs]
            }
          },
        ),
      }
    RemoveInput(i) ->
      Transaction {
        ..self,
        inputs: list.indexed_foldr(
          self.inputs,
          [],
          fn(j, x, xs) {
            if i == j {
              xs
            } else {
              [x, ..xs]
            }
          },
        ),
      }
  }
}

// A simple transaction that forwards the script. No assets/authorization have
// been minted yet.
const scenario_01_value: Value = assets.from_lovelace(42)

const scenario_01: Transaction = {
    let inputs =
      [
        Input {
          output_reference: OutputReference {
            transaction_id: #"7c5abfeef47cc73653a954814caf7361c8a8106788aa0fe65cda94e161d6309d",
            output_index: 1,
          },
          output: Output {
            address: proxy_address,
            value: scenario_01_value,
            datum: NoDatum,
            reference_script: None,
          },
        },
      ]

    let outputs =
      [
        Output {
          address: proxy_address,
          value: scenario_01_value,
          datum: NoDatum,
          reference_script: None,
        },
      ]

    Transaction { ..transaction.placeholder, inputs: inputs, outputs: outputs }
  }

test scenario_01_is_valid() {
  expect Some(from) = list.at(scenario_01.inputs, 0)
  must_forward_script(scenario_01, from, administrator)
}

fn scenario_01_ok_mutation(mutation: Mutation) -> Bool {
  when mutation is {
    AddInput(_, Arbitrary, _) | 
    AddInput(_, Derived(SameDatum), _) | 
    AddOutput(_, Arbitrary, _) | 
    AddOutput(_, Derived(SameDatum), _) | 
    ReplaceInput(_, Derived(Clone), _) -> True

    AddInput(_, Derived(Clone), _) | 
    AddInput(_, Derived(SameAddress), _) | 
    ReplaceInput(_, Arbitrary, _) | 
    ReplaceInput(_, Derived(SameDatum), _) | 
    AddOutput(_, Derived(Clone), _) | 
    AddOutput(_, Derived(SameAddress), _) | 
    RemoveInput(..) -> False

    ReplaceInput(_, Derived(SameAddress), input) ->
      assets.lovelace_of(input.output.value) <= assets.lovelace_of(
        scenario_01_value,
      )
  }
}

fn scenario_01_ko_mutation(mutation: Mutation) -> Bool {
  !scenario_01_ok_mutation(mutation)
}

fn prop_forward_script_scenario_01(mutation: Mutation) {
  label(mutation_to_label(mutation))
  let transaction = apply_mutation(scenario_01, mutation)
  expect Some(from) =
    list.at(
      transaction.inputs,
      when mutation is {
        AddInput(Front, ..) -> 1
        RemoveInput(..) -> fail
        _ -> 0
      },
    )
  must_forward_script(transaction, from, administrator)
}

test prop_forward_script_scenario_01_allowed_mutations(
  mutation via gen_mutation(scenario_01, scenario_01_ok_mutation),
) {
  prop_forward_script_scenario_01(mutation)
}

test prop_forward_script_scenario_01_forbidden_mutations(
  mutation via gen_mutation(scenario_01, scenario_01_ko_mutation),
) fail {
  prop_forward_script_scenario_01(mutation)
}

// -----------------------------------------------------------------------------
// ------------------------------------------------ must_forward_strict_assets -
// -----------------------------------------------------------------------------

test prop_forward_assets_only_lovelace(
  (from, to) via both(gen_ada_only_value(), gen_ada_only_value()),
) {
  must_forward_strict_assets(proxy, from, to)
}

test prop_forward_assets_is_restricted(from via gen_value_with(proxy)) {
  let to = value_restricted_to(from, [proxy])
  must_forward_strict_assets(proxy, from, to)
}

test prop_forward_assets_extranenous(from via gen_value_with(proxy)) fail once {
  must_forward_strict_assets(proxy, from, from)
}

// TODO: Move to stdlib
pub fn value_restricted_to(self: Value, policies: List<PolicyId>) -> Value {
  list.foldr(
    assets.policies(self),
    self |> assets.lovelace_of |> assets.from_lovelace,
    fn(policy_id, value) {
      if list.has(policies, policy_id) {
        dict.foldr(
          assets.tokens(self, policy_id),
          value,
          fn(asset_name, quantity, value) {
            assets.add(value, policy_id, asset_name, quantity)
          },
        )
      } else {
        value
      }
    },
  )
}

// -----------------------------------------------------------------------------
// ---------------------------------------------------------------- generators -
// -----------------------------------------------------------------------------

// TODO: Move to the fuzz library.
fn pick(xs: List<a>) -> Fuzzer<(Int, a)> {
  let ix <- map(int_between(0, list.length(xs) - 1))
  expect Some(x) = list.at(xs, ix)
  (ix, x)
}

fn gen_asset_name() -> Fuzzer<AssetName> {
  bytearray_between(0, 32)
}

fn gen_policy_id() -> Fuzzer<PolicyId> {
  bytearray_between(28, 28)
}

fn gen_ada_only_value() -> Fuzzer<Value> {
  map(int_at_least(1), assets.from_lovelace)
}

fn gen_assets(policy_id: PolicyId, value: Value) -> Fuzzer<Value> {
  let names <- and_then(set_between(gen_asset_name(), 0, 3))
  list.foldr(
    names,
    constant(value),
    fn(asset_name, step) {
      let value <- and_then(step)
      let quantity <- map(int_at_least(1))
      value |> assets.add(policy_id, asset_name, quantity)
    },
  )
}

fn gen_value_with(forced_policy_id: PolicyId) -> Fuzzer<Value> {
  let value <- and_then(gen_ada_only_value())
  let policies <- and_then(set_between(gen_policy_id(), 0, 3))
  list.foldr(
    [forced_policy_id, ..policies],
    constant(value),
    fn(policy_id, step) {
      let value <- and_then(step)
      gen_assets(policy_id, value)
    },
  )
}

fn gen_value() -> Fuzzer<Value> {
  let value <- and_then(gen_ada_only_value())
  let policies <- and_then(set_between(gen_policy_id(), 0, 3))
  list.foldr(
    policies,
    constant(value),
    fn(policy_id, step) {
      let value <- and_then(step)
      gen_assets(policy_id, value)
    },
  )
}

fn gen_address() -> Fuzzer<Address> {
  let address_type <- and_then(int_between(0, 5))
  when address_type is {
    0 -> {
      let payment <- map(bytearray_between(28, 28))
      Address {
        payment_credential: VerificationKey(payment),
        stake_credential: None,
      }
    }
    1 -> {
      let payment <- map(bytearray_between(28, 28))
      Address { payment_credential: Script(payment), stake_credential: None }
    }
    2 -> {
      let payment <- and_then(bytearray_between(28, 28))
      let stake <- map(bytearray_between(28, 28))
      Address {
        payment_credential: VerificationKey(payment),
        stake_credential: Some(Inline(VerificationKey(stake))),
      }
    }
    3 -> {
      let payment <- and_then(bytearray_between(28, 28))
      let stake <- map(bytearray_between(28, 28))
      Address {
        payment_credential: VerificationKey(payment),
        stake_credential: Some(Inline(Script(stake))),
      }
    }
    4 -> {
      let payment <- and_then(bytearray_between(28, 28))
      let stake <- map(bytearray_between(28, 28))
      Address {
        payment_credential: Script(payment),
        stake_credential: Some(Inline(VerificationKey(stake))),
      }
    }
    5 -> {
      let payment <- and_then(bytearray_between(28, 28))
      let stake <- map(bytearray_between(28, 28))
      Address {
        payment_credential: Script(payment),
        stake_credential: Some(Inline(Script(stake))),
      }
    }
    _ -> fail @"unexpected address type"
  }
}

fn gen_datum() -> Fuzzer<Datum> {
  let variant <- and_then(int_between(0, 2))
  when variant is {
    0 -> constant(NoDatum)
    1 -> {
      let hash <- map(bytearray_between(32, 32))
      DatumHash(hash)
    }
    2 -> {
      let i <- map(int())
      InlineDatum(i)
    }
    _ -> fail @"unexpected datum variant"
  }
}

fn gen_reference_script() -> Fuzzer<Option<ScriptHash>> {
  option(bytearray_between(28, 28))
}

fn gen_output() -> Fuzzer<Output> {
  let address <- and_then(gen_address())
  let value <- and_then(gen_value())
  let datum <- and_then(gen_datum())
  let reference_script <- map(gen_reference_script())
  Output { address, value, datum, reference_script }
}

fn gen_output_reference() -> Fuzzer<OutputReference> {
  let transaction_id <- and_then(bytearray_between(32, 32))
  let output_index <- map(int_between(0, 300))
  OutputReference { transaction_id, output_index }
}

fn gen_input() -> Fuzzer<Input> {
  let output_reference <- and_then(gen_output_reference())
  let output <- map(gen_output())
  Input { output_reference, output }
}

fn gen_input_at(position: Position, transaction: Transaction) -> Fuzzer<Input> {
  let predicate =
    when position is {
      Back -> {
        expect Some(last_input) = list.last(transaction.inputs)
        fn(candidate) { compare_input(candidate, last_input) == Greater }
      }
      Front -> {
        expect Some(first_input) = list.head(transaction.inputs)
        fn(candidate) { compare_input(candidate, first_input) == Less }
      }
    }

  gen_input() |> such_that(predicate)
}
