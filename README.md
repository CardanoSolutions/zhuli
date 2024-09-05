# Proxy DReps

A validator to provide hot/cold account management to DReps. The scripts provides an authentication mecanism around an administrator multisig script (m-of-n type), itself granting powers to two sub-scripts to manage stake in two contexts:

- For block-production; or specifically delegation to stake pools and withdrawal of rewards.
- For governance; or specifically voting on governance action and management of DReps metadata.

This is achieved through the use of receipt tokens that are minted alongside the publication of certificates. The minting (resp. burning) of those tokens is tied to the registration (resp. unregistration) of their corresponding certificates.

## Configuration

The validator itself is bound to a particular administrator which can be configured directly in the `aiken.toml`.

```toml
[config.default]
threshold = 1 # How many administrors signatories are required to approve actions

# List of administators (verification key hashes)
[[config.default.administrators]]
bytes = "00000000000000000000000000000000000000000000000000000000"
encoding = "base16"

[[config.default.administrators]]
bytes = "00000000000000000000000000000000000000000000000000000001"
encoding = "base16"
```
