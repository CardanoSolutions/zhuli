# ZhuLi

> [!NOTE]
> A companion command-line tool for managing a hot/cold DRep setup.

## Installing

### Linux / MacOS

```console
❯ curl --proto '=https' --tlsv1.2 -LsSf https://github.com/CardanoSolutions/zhuli/releases/download/0.0.1/zhuli-installer.sh | sh
```

### Windows

```console
❯ powershell -c "irm https://github.com/CardanoSolutions/zhuli/releases/download/0.0.1/zhuli-installer.ps1 | iex"
```

## Getting Started

```console
❯ zhuli --help
```

## Tutorial

In this tutorial, we'll explore how to perform a simple setup with a single cold key (the administrator) delegating to a single hot key (the delegate). More complex setup with multiple administrators and delegates are similar and only require passing extra `--administrator` and `--delegate` arguments accordingly.

#### Pre-requisite

- [x] Define `BLOCKFROST_PROJECT_ID` as an environment variable with a corresponding, valid, [Blockfrost.io](https://blockfrost.io/) api key.
- [x] Have the [`cardano-cli`](https://github.com/IntersectMBO/cardano-cli) readily available, we'll use it for signing and computing key hashes.
- [x] Have an administrator verification and signing keys available as `admin.vk` and `admin.sk` respectively.
- [x] Configure the administrator appropriately in the `aiken.toml` file, and build the validator using `aiken build`.
- [x] Have a  delegate verification and signing keys available as `delegate.vk` and `delegate.sk` respectively.
- [x] Whenever we refer to `$FUEL`, we refer to a UTxO reference locked by a verification key that you can spend freely to cover for fees, deposits and collateral.

#### Delegating

First, let's create an initial delegation transaction. This is the first time we invoke the contract, so it hasn't been published anywhere yet.

```console
zhuli delegate \
  --fuel $FUEL \
  --quorum 1 \
  --delegate $(cardano-cli address key-hash --payment-verification-key-file delegate.vk) \
  --administrator $(cardano-cli address key-hash --payment-verification-key-file admin.vk) \
  --validator $(jq -r ".validators[0].compiledCode" plutus.json) > delegation.unsigned
```

> [!NOTE]
> 1. The `--validator` argument assumes that you are running from the root of the repository. If not, adjust the `plutus.json` path to point to the right blueprint file.
> 2. The `--quorum` argument is optional / redundant here since we only have one delegate anyway. We could omit it.

This command builds a delegation transaction for us, that is ready to be signed. We can inspect the transaction using the `cardano-cli` as such:

```console
cardano-cli debug transaction view --output-yaml --tx-file delegation.unsigned
```

If everything is fine, we can sign and submit the transaction. Note that you'll need to sign _at least_ with the administrator key, as well as any key necessary to authorize the spending of the fuel.

```console
cardano-cli transaction sign \
  --mainnet \
  --signing-key-file admin.sk \
  --tx-file delegation.unsigned \
  --out-file delegation.signed
```

#### Voting

The _delegate_ action above registers the delegate representative in the same it defines the delegate. They are in fact bound, as the drep credential cannot exist without a delegate. However, administrators can always delegate to themselves should they want to get full control back.

Now that the delegate exists, let's vote on a governance proposal. Let's pretend that there's a proposal with id: `ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff#0` and vote positively on it. We will need to grab the UTxO reference to the contract, which is the 1st output of the delegate transaction. Let's pretend its id is `0000000000000000000000000000000000000000000000000000000000000000`.

We build our voting transaction on the proposal as follows:

```console
zhuli vote \
  --yes \
  --delegate $(cardano-cli address key-hash --payment-verification-key-file delegate.vk) \
  --proposal ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff#0 \
  --contract 0000000000000000000000000000000000000000000000000000000000000000#0 \
  --fuel $FUEL > vote.unsigned
```

Note how we specify `--delegate` again here, but with a slightly different semantic. In the `delegate` command, we must specify each delegate that we want to authorize as well the quorum they need to meet for voting. Here, we only specify those who will be authorizing _this specific vote_. In an m-of-n setup, that means we must specify at least `m` delegates at this point, whereas `n` delegates were defined during the `delegate` step.

> [!TIP]
> You also add metadata to the vote using the `--anchor` argument, passing in a URL to a metadata file. ZhuLi takes care of fetching the content and computing its hash.

Our case is simpler here since we only have one delegate anyway. And this time, the transaction requires a signature from them (instead of the administrator), as well as whatever is required to authorize the spending of the fuel UTxO.

```console
cardano-cli transaction sign \
  --mainnet \
  --signing-key-file delegate.sk \
  --tx-file vote.unsigned \
  --out-file vote.signed
```
