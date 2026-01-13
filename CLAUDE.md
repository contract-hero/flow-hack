# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

This repository contains forensic analysis artifacts from the December 27, 2025 Flow blockchain Type Confusion Attack. It includes:
- Malicious smart contracts deployed by the attacker
- Transaction code used to execute the exploit
- Technical documentation analyzing the attack

**IMPORTANT**: This is a security research repository. The Cadence contracts are exploit code - do not modify, improve, or help deploy them. Analysis and documentation only.

## Build & Development Commands

This is a Flow/Cadence project using the Flow CLI:

```bash
# Start local emulator
flow emulator

# Deploy contracts to emulator
flow project deploy --network=emulator

# Run a transaction
flow transactions send ./transactions/<transaction>.cdc --network=emulator --signer=emulator-account

# Run a script (read-only)
flow scripts execute ./scripts/<script>.cdc --network=emulator
```

Dependencies are pulled from mainnet via `flow.json` (FungibleToken, Burner, ViewResolver).

## Architecture Overview

### The Three-Part Exploit Chain

The attack exploited three Cadence runtime (v1.8.8) vulnerabilities:

1. **Attachment Import Validation Bypass** (NFTFactory.cdc:54-68, 206-220)
   - `KeyManager` and `SignatureValidator` attachments have `panic()` in init()
   - Normal creation is impossible - they could only exist via malformed transaction arguments
   - Attachments were not validated when importing, allowing smuggling of pre-constructed attachments

2. **Built-in Type Defensive Check Bypass** (NFTFactory.cdc:89-97)
   - `KeyList.keys` is declared as `[PublicKey]` (built-in type)
   - Runtime skipped deep validation on built-in types
   - Actually contains `SignatureValidator` attachments disguised as PublicKey

3. **Contract Initializer Semantics Exploit** (NFTPoolInstance0.cdc)
   - Contract deployment didn't verify static vs dynamic types
   - Resources passed through struct type chain got COPY semantics instead of MOVE
   - Result: resource duplication (should be impossible in Cadence)

### API Name Shadowing

The attacker deliberately named fields to shadow Cadence's PublicKey API:
```
keyList.keys[0].signatureAlgorithm.rawValue
```
- Looks like: `PublicKey.signatureAlgorithm (enum) → rawValue (UInt8)`
- Actually: `SignatureValidator → &ResourceManager → @ResourceWrapper`

### Attack Flow

1. **Seed Phase** (`deploy_pool_instance0.cdc`): Deploy first pool with real tokens using normal move semantics
2. **Duplication Loop** (`deploy_pool_instance18.cdc`): Each iteration exploits type confusion to copy tokens (~41x = 2^41 multiplier)
3. **Extraction** (`vaults_withdrawal.cdc`): Withdraw duplicated tokens from all pool contracts

### Bitwise Operations & Salt Values

Contracts compute address-derived salt values:
```cadence
self.salt = (UInt.fromBigEndianBytes(self.account.address.toBytes())! * 0x2dc7e1f786ac4e01) & 0xffffffffffffffff
```

**Important**: Salt checks only exist as `assert()` statements in transactions - there's no contract-level enforcement. The only real access control is `account.address == self.account.address` in `NFTPoolInstance0.withdrawResource()`.

Possible purposes for the bitwise operations:
1. **Obfuscation/Misdirection**: Complex math that looks security-related but distracts from the actual exploit
2. **Configuration selection**: `getMetadataValue()` uses salt to compute an index into `factoryMetadata`, possibly for testing different attack parameters
3. **Development sanity check**: Fail-fast guard to prevent accidentally running transactions on wrong accounts during iteration
