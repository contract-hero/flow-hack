# Flow Network Security Incident - December 27, 2025

###### Cries in resource oriented programming 💀. Claude made, don't quote me on this.

## Technical Analysis of the Type Confusion Attack

### Table of Contents

1. [Executive Summary](#executive-summary)
2. [Attack Overview](#attack-overview)
3. [The Three-Part Exploit Chain](#the-three-part-exploit-chain)
4. [Deep Dive: The JSON-CDC Exploit Mechanism](#deep-dive-the-json-cdc-exploit-mechanism)
5. [Contract Analysis](#contract-analysis)
   - [NFTFactory.cdc](#nftfactorycdc)
   - [HotspotNFT.cdc](#hotspotnftcdc)
   - [NFTPoolInterface.cdc](#nftpoolinterfacecdc)
   - [NFTPoolInstance0.cdc](#nftpoolinstance0cdc)
6. [Transaction Analysis: rogue_mint.cdc](#transaction-analysis-rogue_mintcdc)
7. [Hex Values and Obfuscation Techniques](#hex-values-and-obfuscation-techniques)
8. [Attack Timeline](#attack-timeline)
9. [References](#references)

---

## Executive Summary

On December 27, 2025, an attacker exploited a vulnerability in the Flow blockchain's Cadence runtime (v1.8.8) to counterfeit fungible tokens, extracting approximately **$3.9 million USD**. The attack utilized a sophisticated **Type Confusion Attack** that bypassed Cadence's resource linearity guarantees—the fundamental property that resources (like tokens) cannot be copied, only moved.

The attacker deployed over 40 malicious smart contracts in a coordinated sequence, exploiting a three-part vulnerability chain to duplicate token resources. The duplicated tokens included FLOW, USDT, WBTC, WETH, DAI, and several other fungible tokens.

**Key Finding**: The contracts in this repository contain design patterns consistent with the exploit described in the official post-mortem, including `panic()` calls in attachment initializers that make normal instantiation impossible—suggesting these attachments were designed exclusively for exploitation via the validation bypass.

> **Disclaimer**: This analysis combines information from the [official Flow post-mortem](https://flow.com/post/dec-27-technical-post-mortem) with examination of the contracts in this repository. Some details about how specific contract elements were used are inferred from the contract structure and may not represent the exact exploit execution.

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

## Deep Dive: The JSON-CDC Exploit Mechanism

This section answers the critical questions: **How did the attacker create malformed arguments?** and **How could attachments exist if their init() always panics?**

### Understanding JSON-CDC

[JSON-Cadence (JSON-CDC)](https://cadence-lang.org/docs/json-cadence-spec) is the serialization format for Cadence values. When you submit a transaction to Flow:

```
[Your Code] → [JSON-CDC Serialization] → [Network] → [Deserializer] → [Execution]
```

The key insight: **Deserialization reconstructs objects WITHOUT calling init() functions.**

### How Attachments Bypassed init()

When you create an attachment normally in Cadence code:

```cadence
// This would call init() and PANIC:
let manager = attach KeyManager() to someStruct  // → panic("0")!
```

But when importing values from transaction arguments, the runtime reconstructs objects from their serialized form:

```
[Transaction Arguments] → [Deserializer] → [In-memory values]
```

The post-mortem states that attachments "can be imported alongside structs when passed as transaction arguments." This import path appears to bypass normal constructor invocation, allowing the attacker to create attachment instances that would otherwise panic.

**The `panic()` in init() serves as forensic evidence**: These attachments can ONLY exist if instantiated through the exploit path—any `KeyManager` or `SignatureValidator` instance in the wild indicates the exploit was used.

> **Note**: The exact mechanism by which deserialization bypasses init() is inferred from the behavior. The official post-mortem confirms attachments were imported but doesn't detail the internal deserialization process.

### The Inferred Attack Path

Based on the contract structure, we can infer the attacker likely exploited the path through `KeyManager → KeyList → [PublicKey]`:

```
┌─────────────────────────────────────────────────────────────────────┐
│             INFERRED PATH FOR RESOURCE SMUGGLING                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Contract Definitions in NFTFactory.cdc:                             │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ struct KeyList {                                              │   │
│  │     var keys: [PublicKey]  ← DECLARED as array of PublicKey  │   │
│  │ }                                                             │   │
│  │                                                               │   │
│  │ attachment KeyManager for AnyStruct {                         │   │
│  │     var keyList: KeyList                                      │   │
│  │     init() { panic("0") }  ← Never called via deserialization│   │
│  │ }                                                             │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Conceptual Malformed Payload (exact format not documented):        │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                                                               │   │
│  │   Struct with KeyManager attachment                          │   │
│  │     │                                                        │   │
│  │     └─► KeyManager (Part 1: attachment not validated)        │   │
│  │           │                                                  │   │
│  │           └─► keyList: KeyList                               │   │
│  │                 │                                            │   │
│  │                 └─► keys: [PublicKey]                        │   │
│  │                       │                                      │   │
│  │                       └─► DECLARED: PublicKey                │   │
│  │                           ACTUAL: ResourceWrapper bytes      │   │
│  │                                   ↑                          │   │
│  │                           Part 2: Built-in type not checked  │   │
│  │                                                               │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  NOTE: The exact JSON-CDC format for attachments is not publicly    │
│  documented. This diagram represents the conceptual structure.      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### How the Attacker Likely Obtained Resource Bytes

> **Note**: This section describes a plausible method based on the contract capabilities. The exact technique used by the attacker is not detailed in the official post-mortem.

The attacker didn't need to create the malicious attachment to get resource bytes. A plausible approach:

1. **Created a ResourceWrapper legitimately** (this is normal, allowed code):

   ```cadence
   // Step 1: Obtain small amounts of tokens
   let vaults: @[{FungibleToken.Vault}] <- [<- flowVault, <- usdtVault, ...]

   // Step 2: Wrap them (nothing prevents this)
   let wrapper <- NFTFactory.wrapResource(argResource: <- vaults)
   ```

2. **Obtained or crafted the byte representation** needed for the type confusion

3. **Crafted malformed transaction arguments** where:

   - Attachment fields contained invalid types (Part 1 bypass)
   - Built-in type fields contained resource data (Part 2 bypass)

4. **Submitted as transaction arguments**

### The Type Confusion Result

From the official post-mortem:

> "By crafting malformed transaction arguments that bypassed runtime validation, the attacker caused Cadence to **statically treat a value as a struct (copy semantics) while dynamically executing it as a resource (move semantics)**."

After the exploit, the runtime had a value that was:

| Perspective                        | Type                | Semantics               |
| ---------------------------------- | ------------------- | ----------------------- |
| **Static** (type system view)      | Value type (struct) | **COPYABLE**            |
| **Dynamic** (actual runtime value) | Resource type       | **Should be MOVE-ONLY** |

This mismatch is the **type confusion**—the runtime applied copy semantics to what was actually a resource.

### The Duplication via Contract Deployment

```cadence
// Attacker calls:
account.contracts.add(
    name: "NFTPoolInstance0",
    code: poolContractCode,
    typeConfusedValue  // ← Static: struct (copy) | Dynamic: resource (move)
)
```

The runtime:

1. Sees `typeConfusedValue` as a struct → **copies** the argument
2. Passes the "copy" to `NFTPoolInstance0.init()`
3. Init treats it as a resource → stores it normally
4. **Original still exists** (because it was "copied")
5. **Duplicate now exists** in the new contract

Repeat 42 times → 2^42 = 4.4 trillion multiplication.

### Why This Matters for the Contracts in This Repo

The contracts appear specifically designed to enable this attack:

| Contract Element                       | Inferred Purpose                                    |
| -------------------------------------- | --------------------------------------------------- |
| `KeyManager` attachment with `panic()` | Can only exist via exploit (init always panics)     |
| `KeyList` with `[PublicKey]`           | Built-in type used in Part 2 of exploit chain       |
| `ResourceWrapper` / `ResourceManager`  | Wrapping utilities for resource handling            |
| `NFTPoolInstance0.init(argResource:)`  | Contract deployment triggers duplication (Part 3)   |
| Salt-based authorization               | Ensures only deployer account can extract resources |

> **Note**: The exact mapping of contract elements to exploit stages is inferred from the contract structure and the post-mortem's description of the three-part exploit chain.

---

## Contract Analysis

### NFTFactory.cdc

**Purpose**: Core exploit infrastructure providing:

- Attachments for Part 1 exploit (`KeyManager`, `SignatureValidator`)
- Built-in type container for Part 2 exploit (`KeyList` with `PublicKey`)
- Resource wrapping utilities (`ResourceWrapper`, `ResourceManager`)
- Address-based authorization via salt computation

**Key Components**:

| Component                       | Role in Attack                                           |
| ------------------------------- | -------------------------------------------------------- |
| `KeyManager` attachment         | Part 1 - Smuggling malformed data via attachments        |
| `SignatureValidator` attachment | Part 1 - Additional smuggling vector                     |
| `KeyList` struct                | Part 2 - Contains `PublicKey` to bypass defensive checks |
| `ResourceWrapper`               | Wraps duplicated token vaults for extraction             |
| `ResourceManager`               | Manages wrapped resources with swap semantics            |
| `salt`                          | Authorization - ensures only attacker can use contracts  |

**Authorization Mechanism**:

```cadence
// Computed from deployer's address - unique fingerprint
self.salt = (UInt.fromBigEndianBytes(self.account.address.toBytes())!
             * 0x2dc7e1f786ac4e01) & 0xffffffffffffffff
```

---

### HotspotNFT.cdc

**Purpose**: Vault container contract. Its exact role in the attack is unclear—it may have been deployed as part of the attack infrastructure but the official post-mortem does not specifically mention it. The contract provides structures for holding `FungibleToken.Vault` arrays.

**Key Components**:

| Component          | Apparent Purpose                                           |
| ------------------ | ---------------------------------------------------------- |
| `Hotspot` resource | Container for `FungibleToken.Vault` array                  |
| `NFT` resource     | Wrapper for Hotspot with swap-based withdrawal             |
| `salt`             | Address-based value (different multiplier than NFTFactory) |

**Vault Container**:

```cadence
access(all) resource Hotspot {
    access(all) var vaults: @[{FungibleToken.Vault}]
}
```

> **Note**: While this contract was deployed by the attacker, its direct involvement in the token duplication exploit is not confirmed by the official post-mortem.

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

| Parameter      | Type       | Description                                   |
| -------------- | ---------- | --------------------------------------------- |
| `contractName` | `String`   | Pool contract name (e.g., "NFTPoolInstance0") |
| `identifiers`  | `[String]` | Storage path identifiers for target vaults    |

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

| Contract   | Formula                                               |
| ---------- | ----------------------------------------------------- |
| NFTFactory | `(address * 0x2dc7e1f786ac4e01) & 0xffffffffffffffff` |
| HotspotNFT | `(address * 0x6fb64c0ce08a525) & 0xffffffffffffffff`  |

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

## Complete Attack Flow Summary

The following is a reconstruction based on the official post-mortem and analysis of the deployed contracts. Steps marked with ⚠️ are inferred from contract structure.

```
┌─────────────────────────────────────────────────────────────────────┐
│                      COMPLETE ATTACK FLOW                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. PREPARATION (confirmed)                                          │
│     ├── Deploy attack contracts (40+ contracts deployed)            │
│     ├── Obtain small amounts of 13 target tokens                    │
│     └── Create ResourceWrapper containing token vaults              │
│                                                                      │
│  2. CRAFT MALFORMED TRANSACTION ARGUMENTS (confirmed mechanism)     │
│     ├── Part 1: Exploit attachment validation bypass                │
│     ├── Part 2: Use PublicKey (built-in) to skip defensive checks  │
│     └── ⚠️ Exact structure inferred from contracts                  │
│                                                                      │
│  3. ACHIEVE TYPE CONFUSION (confirmed)                               │
│     ├── Runtime treats value as struct (copy semantics)            │
│     └── Actual value contains resource (should be move semantics)  │
│                                                                      │
│  4. DUPLICATE VIA CONTRACT DEPLOYMENT (confirmed)                    │
│     ├── Part 3: account.contracts.add() static/dynamic mismatch    │
│     ├── Struct semantics → argument COPIED                         │
│     ├── Resource received → stored in new contract                 │
│     └── RESOURCE DUPLICATED!                                        │
│                                                                      │
│  5. REPEAT ~42 TIMES (confirmed)                                     │
│     ├── Each iteration doubles the tokens                          │
│     ├── 2^42 = 4,398,046,511,104 multiplication                    │
│     └── All amounts are multiples of 2^42                          │
│                                                                      │
│  6. EXTRACTION (confirmed)                                           │
│     ├── Withdraw from pool contracts                                │
│     └── Deposit duplicated tokens to attacker's vaults             │
│                                                                      │
│  7. LIQUIDATION (confirmed)                                          │
│     ├── Transfer to exchange deposit addresses                     │
│     ├── Swap on DEXs (IncrementFi, KittyPunch)                     │
│     └── Bridge off-network (Celer, deBridge, Stargate)             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Attack Timeline

| Time (PST)    | Block Height | Event                                        |
| ------------- | ------------ | -------------------------------------------- |
| Dec 26, 23:25 | 137363398    | Attack contracts deployed                    |
| Dec 26, 23:35 | -            | Token duplication begins                     |
| Dec 26, 23:36 | -            | Transfers to secondary accounts              |
| Dec 26, 23:42 | -            | First deposits to exchanges                  |
| Dec 27, 00:06 | -            | Assets bridged via Celer, deBridge, Stargate |
| Dec 27, 01:00 | -            | Exchange sell pressure detected              |
| Dec 27, 01:30 | -            | Anomaly detection triggered                  |
| Dec 27, 05:21 | -            | Final attacker transfer                      |
| Dec 27, 05:23 | 137390190    | **Network halted by validators**             |
| Dec 29, 05:00 | -            | Network restored (read/write)                |

---

## References

- [Flow Security Incident Post-Mortem](https://flow.com/post/dec-27-technical-post-mortem)
- [JSON-Cadence Data Interchange Format](https://cadence-lang.org/docs/json-cadence-spec)
- [Cadence Language Documentation](https://cadence-lang.org/)
- Attack Transaction: `11db77fa805840242c1a457fcab91fa69e7eb5dc835b45f3a296f38be2929aca`
- Primary Attack Address: `0xfd595328d97d33d5`

---

## Appendix: Contract File Summary

| File                   | Lines | Purpose                        |
| ---------------------- | ----- | ------------------------------ |
| `NFTFactory.cdc`       | 227   | Core exploit infrastructure    |
| `HotspotNFT.cdc`       | 144   | Token vault container          |
| `NFTPoolInterface.cdc` | 30    | Pool contract interface        |
| `NFTPoolInstance0.cdc` | 82    | Duplication point (one of ~42) |
| `rogue_mint.cdc`       | 153   | Extraction transaction         |

---

_Analysis conducted January 2026_
