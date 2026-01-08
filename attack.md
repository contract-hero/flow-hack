# Flow Network Security Incident - December 27, 2025
## Technical Analysis of the Type Confusion Attack

### Table of Contents
1. [Executive Summary](#executive-summary)
2. [Attack Overview](#attack-overview)
3. [The Three-Part Exploit Chain](#the-three-part-exploit-chain)
4. [Contract Analysis](#contract-analysis)
   - [NFTFactory.cdc](#nftfaborycdc)
   - [HotspotNFT.cdc](#hotspotnftcdc)
   - [NFTPoolInterface.cdc](#nftpoolinterfacecdc)
   - [NFTPoolInstance0.cdc](#nftpoolinstance0cdc)
5. [Transaction Analysis: rogue_mint.cdc](#transaction-analysis-rogue_mintcdc)
6. [Hex Values and Obfuscation Techniques](#hex-values-and-obfuscation-techniques)
7. [Attack Timeline](#attack-timeline)
8. [Financial Impact](#financial-impact)
9. [References](#references)

---

## Executive Summary

On December 27, 2025, an attacker exploited a vulnerability in the Flow blockchain's Cadence runtime (v1.8.8) to counterfeit fungible tokens, extracting approximately **$3.9 million USD**. The attack utilized a sophisticated **Type Confusion Attack** that bypassed Cadence's resource linearity guarantees—the fundamental property that resources (like tokens) cannot be copied, only moved.

The attacker deployed over 40 malicious smart contracts in a coordinated sequence, exploiting a three-part vulnerability chain to duplicate token resources. The duplicated tokens included FLOW, USDT, WBTC, WETH, DAI, and several other fungible tokens.

**Key Finding**: The contracts analyzed in this repository contain deliberate design patterns that prove they were purpose-built for exploitation, including `panic()` calls in attachment initializers that make normal instantiation impossible.

---

## Attack Overview

### How Cadence Normally Protects Resources

Cadence uses a **resource-oriented programming model** where tokens are not simple ledger entries but programmable objects that:
- Cannot be copied (only moved)
- Cannot be implicitly discarded (must be explicitly destroyed)
- Exist directly in user account storage

This is enforced through **move semantics**: when you pass a resource to a function, the original is invalidated. You cannot have two references to the same resource.

### What the Attack Achieved

The attacker found a way to make the Cadence runtime:
1. **Statically** treat a value as a **struct** (which uses copy semantics)
2. **Dynamically** execute it as a **resource** (which should use move semantics)

This mismatch allowed the attacker to **copy resources**, effectively counterfeiting tokens.

### Duplication Mathematics

The attacker:
1. Obtained small amounts of 13 different tokens
2. Deployed ~42 NFTPoolInstance contracts, each deployment duplicating the tokens
3. Each duplication doubles the amount: 2^42 = **4,398,046,511,104** multiplier
4. Result: 87.96 billion units per token duplicated

---

## The Three-Part Exploit Chain

### Part 1: Attachment Import Validation Bypass

**Vulnerability**: Cadence attachments (a feature to extend types) were not fully validated during transaction argument import. Attachment fields could contain values with incorrect runtime types that weren't checked against their declared static types.

**Exploitation**: The attacker sent malformed transaction arguments where:
- Attachments were declared with certain static types
- Actual runtime values had DIFFERENT types
- The validator failed to reject these mismatches

**Evidence in Code**: `NFTFactory.cdc` contains two attachments with `panic()` in their initializers:

```cadence
access(all) attachment KeyManager for AnyStruct {
    init() {
        self.keyList = KeyList()
        panic("0")  // Can NEVER be created normally
    }
}

access(all) attachment SignatureValidator for AnyStruct {
    init(ref: &ResourceManager) {
        self.signatureAlgorithm = ref
        panic("1")  // Can NEVER be created normally
    }
}
```

The `panic()` calls prove these attachments were designed **exclusively** for the exploit—they could only be instantiated through malformed arguments that bypassed validation.

---

### Part 2: Built-in Type Defensive Check Bypass

**Vulnerability**: Cadence employed defensive runtime checks to catch type-confused values, but these checks were skipped for built-in types like `PublicKey` since they're normally only created by the runtime itself.

**Exploitation**: The attacker:
1. Declared a value as `PublicKey` (built-in type)
2. Encoded a **resource-containing structure** in its place
3. The runtime skipped deep validation
4. A resource was successfully hidden inside a value type

**Evidence in Code**: `NFTFactory.cdc` contains:

```cadence
access(all) struct KeyList {
    access(all) var keys: [PublicKey]  // Built-in type exploited for bypass
    
    init() {
        self.keys = []
    }
}
```

The `PublicKey` array provided the vector for smuggling resources inside structs.

---

### Part 3: Contract Initializer Semantics Exploit

**Vulnerability**: When deploying contracts via `account.contracts.add()`, the runtime did not verify that the static types of initializer arguments matched the contract's init parameter types. Only dynamic types were checked.

**Exploitation**: 
1. Attacker prepared a `ResourceWrapper` containing token vaults
2. Through Parts 1 & 2, this resource was disguised as a struct (statically)
3. When passed to contract deployment:
   - Calling context saw a STRUCT → applied **copy** semantics
   - Contract init saw a RESOURCE → stored it normally
   - **Result**: Resource was duplicated

**Evidence in Code**: `NFTPoolInstance0.cdc`:

```cadence
init(argResource: @NFTFactory.ResourceWrapper) {
    // This received a COPIED resource due to type confusion
    self.resourcePool <- [<- argResource]
}
```

---

## Contract Analysis

### NFTFactory.cdc

**Purpose**: Core exploit infrastructure providing:
- Attachments for Part 1 exploit (`KeyManager`, `SignatureValidator`)
- Built-in type container for Part 2 exploit (`KeyList` with `PublicKey`)
- Resource wrapping utilities (`ResourceWrapper`, `ResourceManager`)
- Address-based authorization via salt computation

**Key Components**:

| Component | Role in Attack |
|-----------|---------------|
| `KeyManager` attachment | Part 1 - Smuggling malformed data via attachments |
| `SignatureValidator` attachment | Part 1 - Additional smuggling vector |
| `KeyList` struct | Part 2 - Contains `PublicKey` to bypass defensive checks |
| `ResourceWrapper` | Wraps duplicated token vaults for extraction |
| `ResourceManager` | Manages wrapped resources with swap semantics |
| `salt` | Authorization - ensures only attacker can use contracts |

**Authorization Mechanism**:
```cadence
// Computed from deployer's address - unique fingerprint
self.salt = (UInt.fromBigEndianBytes(self.account.address.toBytes())! 
             * 0x2dc7e1f786ac4e01) & 0xffffffffffffffff
```

---

### HotspotNFT.cdc

**Purpose**: Container contract for holding duplicated token vaults.

**Key Components**:

| Component | Role in Attack |
|-----------|---------------|
| `Hotspot` resource | Container for `FungibleToken.Vault` array |
| `NFT` resource | Wrapper for Hotspot with swap-based withdrawal |
| `salt` | Secondary authorization (different multiplier than NFTFactory) |

**Vault Container**:
```cadence
access(all) resource Hotspot {
    access(all) var vaults: @[{FungibleToken.Vault}]
    // Stores the duplicated token vaults
}
```

---

### NFTPoolInterface.cdc

**Purpose**: Interface implemented by all pool contracts, enabling uniform access pattern.

```cadence
access(all) contract interface NFTPoolInterface {
    access(all) fun withdrawResource(account: auth(Storage) &Account): @NFTFactory.ResourceWrapper?
}
```

This interface allowed `rogue_mint.cdc` to iterate through all ~42 pool contracts by name.

---

### NFTPoolInstance0.cdc

**Purpose**: The actual duplication point. Contract deployment with this init function caused resource copying.

**Critical Code**:
```cadence
init(argResource: @NFTFactory.ResourceWrapper) {
    // THE DUPLICATION POINT
    // Due to type confusion:
    // - Caller thought argResource was a struct (copy semantics)
    // - This init treats it as a resource (move semantics)
    // - Result: Resource is COPIED, not moved
    self.resourcePool <- [<- argResource]
}
```

**Security Check**:
```cadence
access(all) fun withdrawResource(account: auth(Storage) &Account): @NFTFactory.ResourceWrapper? {
    // Only deploying account can withdraw
    assert(account.address == self.account.address, message: "4")
    // ...
}
```

---

## Transaction Analysis: rogue_mint.cdc

**Purpose**: Extraction transaction to collect duplicated tokens from pool contracts and storage.

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `contractName` | `String` | Pool contract name (e.g., "NFTPoolInstance0") |
| `identifiers` | `[String]` | Storage path identifiers for target vaults |

### Target Tokens

The transaction targeted 13 token vaults:

```
flowTokenVault          - Native FLOW token
ceUSDTVault             - Celer-bridged USDT
usdcFlowVault           - USDC on Flow
ceDAIVault              - Celer-bridged DAI
ceWETHVault             - Celer-bridged WETH
ceWBTCVault             - Celer-bridged WBTC
ceBNBVault              - Celer-bridged BNB
ceBUSDVault             - Celer-bridged BUSD
+ 5 EVM-bridged tokens
```

### Execution Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    rogue_mint.cdc Execution                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. POOL EXTRACTION                                              │
│     ┌──────────────────────────────────────────────┐            │
│     │ poolContract.withdrawResource(account: acct) │            │
│     │              ↓                                │            │
│     │ resourceWrapper.unwrap() as! @[Vault]        │            │
│     │              ↓                                │            │
│     │ depositVaultsToStorage(vaults)               │            │
│     └──────────────────────────────────────────────┘            │
│                                                                  │
│  2. AUTHORIZATION CHECK                                          │
│     ┌──────────────────────────────────────────────┐            │
│     │ computedSalt = (address * 0x2dc7e1f786ac4e01)│            │
│     │               & 0xffffffffffffffff            │            │
│     │ assert(computedSalt == NFTFactory.salt)      │            │
│     └──────────────────────────────────────────────┘            │
│     ⚠️ Only attacker's account passes this check                │
│                                                                  │
│  3. STORAGE EXTRACTION                                           │
│     ┌──────────────────────────────────────────────┐            │
│     │ load ResourceManager from "nftpool" path     │            │
│     │              ↓                                │            │
│     │ manager.getWrapper().unwrap()                │            │
│     │              ↓                                │            │
│     │ depositVaultsToStorage(vaults)               │            │
│     └──────────────────────────────────────────────┘            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Helper Function

```cadence
fun depositVaultsToStorage(vaults: @[{FungibleToken.Vault}]) {
    for i in InclusiveRange(0, identifiers.length - 1) {
        let storagePath = StoragePath(identifier: identifiers[i])!
        let targetVault = acct.storage.borrow<...>(from: storagePath)!
        targetVault.deposit(from: <- vaults.removeFirst())
    }
    destroy vaults
}
```

This deposits each extracted vault into the attacker's corresponding storage path.

---

## Hex Values and Obfuscation Techniques

### Salt Computation

Both contracts compute a `salt` from the deploying account's address:

| Contract | Formula |
|----------|---------|
| NFTFactory | `(address * 0x2dc7e1f786ac4e01) & 0xffffffffffffffff` |
| HotspotNFT | `(address * 0x6fb64c0ce08a525) & 0xffffffffffffffff` |

**Purpose**:
- Creates a deterministic but hard-to-reverse fingerprint
- Acts as authorization: only the original deployer's address produces matching salt
- Different multipliers create distinct salts per contract

### Index Calculation (Obfuscation)

```cadence
// NFTFactory
let key: UInt = 0x13e7a630506419d5
let index = (((self.salt ^ key ^ 0xffffffffffffffff) + 1) >> 64)

// HotspotNFT  
let key: UInt = 0x7ec8f8742628c6c9
let index = (((self.salt ^ key ^ 0xffffffffffffffff) + 1) >> 64)
```

**Breakdown**:
1. `salt ^ key` - XOR with magic constant
2. `^ 0xffffffffffffffff` - Bitwise NOT (flip all bits)
3. `+ 1` - Add one (can cause overflow)
4. `>> 64` - Right shift by 64 bits

**Result**: Returns 0, 1, 2, or 3 depending on overflow behavior

This selects values from metadata maps:
```cadence
// NFTFactory
factoryMetadata = {
    1: 0xab8d79837ca9e79c,
    2: 0x54a47930f6cb3dc4,
    3: 0x8a6c0dbd3aef1bff
}

// HotspotNFT
nftMetadata = {
    1: 0x35347ac7cac47a09,
    2: 0xa6c60934b5f161b1,
    3: 0x43c17dedd778cf72
}
```

**Purpose**: Likely obfuscation to complicate analysis and potentially select different attack configurations based on deploying account.

---

## Attack Timeline

| Time (PST) | Block Height | Event |
|------------|--------------|-------|
| Dec 26, 23:25 | 137363398 | Attack contracts deployed |
| Dec 26, 23:35 | - | Token duplication begins |
| Dec 26, 23:36 | - | Transfers to secondary accounts |
| Dec 26, 23:42 | - | First deposits to exchanges |
| Dec 27, 00:06 | - | Assets bridged via Celer, deBridge, Stargate |
| Dec 27, 01:00 | - | Exchange sell pressure detected |
| Dec 27, 01:30 | - | Anomaly detection triggered |
| Dec 27, 05:21 | - | Final attacker transfer |
| Dec 27, 05:23 | 137390190 | **Network halted by validators** |
| Dec 29, 05:00 | - | Network restored (read/write) |

---

## Financial Impact

### Duplicated Amounts

| Token | Amount Duplicated |
|-------|-------------------|
| FLOW | 87,960,930,222.08 |
| ceUSDT | 87,960,930,222.08 |
| stgUSDC | 87,960,930,222.08 |
| USDC.e | 87,960,930,222.08 |
| ceDAI | 87,960,930,222.08 |
| USDF | 87,960,930,222.08 |
| TRUMP | 87,960,930,222.08 |
| ceBUSD | 87,960,930,222.08 |
| ceWETH | 879,609,302.22 |
| WETH | 879,609,302.22 |
| ceBNB | 879,609,302.22 |
| WBTC | 8,796,093.02 |
| ceWBTC | 87,960,930.22 |

### Outcome

| Metric | Value |
|--------|-------|
| Total Duplicated (nominal) | Trillions of USD |
| **Actual Extracted** | **~$3.9M USD** |
| Recovered by Exchanges | 484,434,923 FLOW |
| % Contained | 99.25%+ |

The vast majority of counterfeit assets were frozen by exchanges or contained on-chain before liquidation.

---

## References

- [Flow Security Incident Post-Mortem](https://flow.com/post/dec-27-technical-post-mortem)
- [Cadence Language Documentation](https://cadence-lang.org/)
- Attack Transaction: `11db77fa805840242c1a457fcab91fa69e7eb5dc835b45f3a296f38be2929aca`
- Primary Attack Address: `0xfd595328d97d33d5`

---

## Appendix: Contract File Summary

| File | Lines | Purpose |
|------|-------|---------|
| `NFTFactory.cdc` | 227 | Core exploit infrastructure |
| `HotspotNFT.cdc` | 144 | Token vault container |
| `NFTPoolInterface.cdc` | 30 | Pool contract interface |
| `NFTPoolInstance0.cdc` | 82 | Duplication point (one of ~42) |
| `rogue_mint.cdc` | 153 | Extraction transaction |

---

*Analysis conducted January 2026*
