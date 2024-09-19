
<p align="center">
  <img width="500" src=".github/logo.png" />
  <p align="center">
    <a href="https://github.com/CardanoSolutions/zhuli/releases"><img src="https://img.shields.io/github/release/CardanoSolutions/zhuli?style=for-the-badge" /></a>
    <a href="https://github.com/CardanoSolutions/zhuli/actions/workflows/continuous-integration.yml"><img src="https://img.shields.io/github/actions/workflow/status/CardanoSolutions/zhuli/continuous-integration.yml?style=for-the-badge" /></a>
    <a href="https://github.com/CardanoSolutions/zhuli/blob/main/LICENSE"><img src="https://img.shields.io/github/license/CardanoSolutions/zhuli?style=for-the-badge" /></a>
  </p>
</p>

## Overview

A validator & companion comman-line tool to provide hot/cold account management to delegate representatives (a.k.a DReps) on Cardano. The on-chain validator provides an authentication mecanism for an administrator multisig script (m-of-n type), itself granting powers to multisig-like delegate to manage voting stake rights.

### Features

- [x] Fixed DRep ID for unlimited delegates, entirely defined by the administrator configuration.
- [x] Delegation of voting rights as a single transaction.
- [x] Revokation of a delegate as a single transaction.
- [x] Revokation & redelegation possible as a single transaction.
- [x] No datum, the state is fully captured in minted assets trapped in the validator.
- [x] Simplified off-chain management and contract flow thanks to a [companion command-line tool](./cli)

### Todo

- [ ] Extend the setup to also support a second type of delegate for block production rights.

## Configuration

The administrator script can be configured direction in the `aiken.toml` as follows:

```toml
[config.default]
quorum = 1 # How many administrors signatories are required to approve actions

# List of administators (verification key hashes)
[[config.default.administrators]]
bytes = "000000000000000000000000000000000000000000000000000a11ce"
encoding = "base16"

[[config.default.administrators]]
bytes = "00000000000000000000000000000000000000000000000000000b0b"
encoding = "base16"
```

> [!TIP]
> Different keys can be configured for different environments. Instead of `default`, use whatever environment name suits you and re-compile the contract accordingly using aiken's cli. For example, you can define custom keys for an environment `foo` as:
>
> ```toml
> [config.foo]
> quorum = 1
>
> [[config.foo.administrators]]
> bytes = "0000000000000000000000000000000000000000000000000000f00"
> encoding = "base16"
> ```
>
> Then, using `aiken`, simply do:
>
> ```
> aiken build --env foo
> ```
