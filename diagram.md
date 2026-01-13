# Flow Network Attack - Mermaid Diagrams

Visual representations of the December 27, 2025 Type Confusion Attack.

## Complete Attack Flow

```mermaid
flowchart TB
    subgraph PREP["1. PREPARATION"]
        P1[Deploy NFTFactory.cdc]
        P2[Deploy NFTPoolInterface.cdc]
        P3[Deploy HotspotNFT.cdc]
        P4[Obtain 13 target tokens]
        P1 --> P2 --> P3 --> P4
    end

    subgraph SEED["2. SEED PHASE (deploy_pollinstance0.cdc)"]
        S1[Withdraw tokens from vaults]
        S2[Wrap into ResourceWrapper]
        S3["Deploy NFTPoolInstance0<br/>with MOVE semantics (←)"]
        S4[Real tokens in first pool]
        S1 --> S2 --> S3 --> S4
    end

    subgraph CRAFT["3. CRAFT MALFORMED ARGUMENTS"]
        C1["Create EmptyStruct with<br/>smuggled KeyManager attachment"]
        C2["KeyManager contains KeyList<br/>with 'PublicKey' array"]
        C3["Actually SignatureValidator<br/>disguised as PublicKey"]
        C1 --> C2 --> C3
    end

    subgraph LOOP["4. DUPLICATION LOOP (×41 iterations)"]
        L1[Extract from previous pool]
        L2[Merge with storage]
        L3[Create ResourceManager]
        L4[Access smuggled KeyManager]
        L5["Cast 'PublicKey' to<br/>SignatureValidator"]
        L6[Point reference to ResourceManager]
        L7["Deploy next pool with<br/>keyList.keys[0].signatureAlgorithm.rawValue"]
        L8{{"RESOURCE DUPLICATED!<br/>2× tokens"}}
        L1 --> L2 --> L3 --> L4 --> L5 --> L6 --> L7 --> L8
        L8 -.->|"Repeat 41×"| L1
    end

    subgraph EXTRACT["5. EXTRACTION (rogue_mint.cdc)"]
        E1[Verify salt authorization]
        E2[Withdraw from all pools]
        E3[Unwrap ResourceWrappers]
        E4[Deposit to attacker vaults]
        E1 --> E2 --> E3 --> E4
    end

    subgraph LIQUID["6. LIQUIDATION"]
        X1[Transfer to exchanges]
        X2["Swap on DEXs<br/>(IncrementFi, KittyPunch)"]
        X3["Bridge off-network<br/>(Celer, deBridge, Stargate)"]
        X1 --> X2 --> X3
    end

    PREP --> SEED --> CRAFT --> LOOP --> EXTRACT --> LIQUID

    style L8 fill:#ff6b6b,stroke:#c92a2a,color:#fff
    style LOOP fill:#fff3bf,stroke:#f59f00
```

## Type Confusion Chain

```mermaid
flowchart LR
    subgraph STATIC["STATIC TYPE (what runtime sees)"]
        direction TB
        ST1["EmptyStruct"]
        ST2["KeyManager<br/>(attachment)"]
        ST3["KeyList<br/>(struct)"]
        ST4["[PublicKey]<br/>(built-in array)"]
        ST5["signatureAlgorithm<br/>(appears to be SignatureAlgorithm enum)"]
        ST6["rawValue<br/>(appears to be UInt8)"]
        ST1 --> ST2 --> ST3 --> ST4 --> ST5 --> ST6
    end

    subgraph DYNAMIC["DYNAMIC TYPE (actual values)"]
        direction TB
        DT1["EmptyStruct<br/>+ attachments"]
        DT2["KeyManager<br/>(smuggled)"]
        DT3["KeyList"]
        DT4["SignatureValidator<br/>(disguised)"]
        DT5["&ResourceManager<br/>(reference)"]
        DT6["@ResourceWrapper<br/>(RESOURCE!)"]
        DT1 --> DT2 --> DT3 --> DT4 --> DT5 --> DT6
    end

    ST6 -.->|"COPY semantics applied"| RESULT
    DT6 -.->|"Should be MOVE"| RESULT
    RESULT{{"TYPE CONFUSION<br/>Resource gets COPIED!"}}

    style RESULT fill:#ff6b6b,stroke:#c92a2a,color:#fff
    style DT6 fill:#ffa94d,stroke:#fd7e14
    style ST6 fill:#69db7c,stroke:#37b24d
```

## Three-Part Exploit Chain

```mermaid
flowchart TB
    subgraph PART1["PART 1: Attachment Validation Bypass"]
        A1["Craft malformed JSON-CDC<br/>transaction arguments"]
        A2["EmptyStruct arrives with<br/>KeyManager already attached"]
        A3["KeyManager.init() never called<br/>(would panic)"]
        A1 --> A2 --> A3
    end

    subgraph PART2["PART 2: Built-in Type Bypass"]
        B1["KeyList.keys declared as [PublicKey]"]
        B2["Runtime skips deep validation<br/>on built-in types"]
        B3["Actually contains<br/>SignatureValidator attachments"]
        B1 --> B2 --> B3
    end

    subgraph PART3["PART 3: Contract Init Semantics"]
        C1["Pass type-confused value to<br/>account.contracts.add()"]
        C2["Static type: struct chain<br/>→ COPY semantics"]
        C3["Dynamic type: resource<br/>→ should be MOVE"]
        C4{{"DUPLICATION!"}}
        C1 --> C2 --> C3 --> C4
    end

    PART1 -->|"Smuggles attachments"| PART2
    PART2 -->|"Hides resources in structs"| PART3

    style C4 fill:#ff6b6b,stroke:#c92a2a,color:#fff
```

## API Shadowing Obfuscation

```mermaid
flowchart LR
    subgraph REAL["Real Cadence API"]
        R1["PublicKey"]
        R2[".signatureAlgorithm"]
        R3["SignatureAlgorithm<br/>(enum)"]
        R4[".rawValue"]
        R5["UInt8"]
        R1 --> R2 --> R3 --> R4 --> R5
    end

    subgraph FAKE["Attacker's Fake API"]
        F1["'PublicKey'<br/>(actually SignatureValidator)"]
        F2[".signatureAlgorithm"]
        F3["&ResourceManager<br/>(reference)"]
        F4[".rawValue"]
        F5["@ResourceWrapper<br/>(resource!)"]
        F1 --> F2 --> F3 --> F4 --> F5
    end

    REAL -.->|"Names shadow<br/>real API"| FAKE

    style F5 fill:#ff6b6b,stroke:#c92a2a,color:#fff
    style R5 fill:#69db7c,stroke:#37b24d
```

## Duplication Mathematics

```mermaid
flowchart LR
    subgraph MATH["Exponential Growth"]
        I0["NFTPoolInstance0<br/>SEED: Real tokens"]
        I1["Instance1<br/>2× tokens"]
        I2["Instance2<br/>4× tokens"]
        I3["Instance3<br/>8× tokens"]
        I4["..."]
        I41["Instance41<br/>2^41 × tokens"]
        
        I0 -->|"×2"| I1 -->|"×2"| I2 -->|"×2"| I3 -->|"×2"| I4 -->|"×2"| I41
    end

    RESULT["2^41 ≈ 2.2 TRILLION<br/>multiplication factor"]
    I41 --> RESULT

    style I0 fill:#69db7c,stroke:#37b24d
    style RESULT fill:#ff6b6b,stroke:#c92a2a,color:#fff
```

## Attack Timeline

```mermaid
timeline
    title December 27, 2025 Attack Timeline (PST)
    
    section Dec 26
        23:25 : Attack contracts deployed
              : Block 137363398
        23:35 : Token duplication begins
              : ~41 iterations
        23:36 : Transfers to secondary accounts
        23:42 : First deposits to exchanges

    section Dec 27
        00:06 : Assets bridged off-network
              : Celer, deBridge, Stargate
        01:00 : Exchange sell pressure detected
        01:30 : Anomaly detection triggered
        05:21 : Final attacker transfer
        05:23 : Network HALTED
              : Block 137390190

    section Dec 29
        05:00 : Network restored
              : Read/write access
```

## Contract Relationships

```mermaid
classDiagram
    class NFTFactory {
        +salt: UInt
        +wrapResource()
        +createManager()
        +getStoragePath()
    }
    
    class KeyManager {
        <<attachment>>
        +keyList: KeyList
        +getKeyList()
        -init() panics!
    }
    
    class KeyList {
        <<struct>>
        +keys: [PublicKey]
        Actually SignatureValidator
    }
    
    class SignatureValidator {
        <<attachment>>
        +signatureAlgorithm: &ResourceManager
        +setSignatureAlgorithm()
        -init() panics!
    }
    
    class ResourceManager {
        <<resource>>
        +rawValue: @ResourceWrapper
        +getWrapper()
    }
    
    class ResourceWrapper {
        <<resource>>
        +resource: @[AnyResource]
        +unwrap()
    }
    
    class EmptyStruct {
        <<struct>>
        Carrier for attachments
    }
    
    class NFTPoolInstance {
        <<contract>>
        +resourcePool: @[ResourceWrapper]
        +withdrawResource()
    }

    NFTFactory *-- KeyManager : defines
    NFTFactory *-- KeyList : defines
    NFTFactory *-- SignatureValidator : defines
    NFTFactory *-- ResourceManager : defines
    NFTFactory *-- ResourceWrapper : defines
    NFTFactory *-- EmptyStruct : defines
    
    EmptyStruct <|-- KeyManager : attached to
    KeyManager --> KeyList : contains
    KeyList --> SignatureValidator : disguised as PublicKey
    SignatureValidator --> ResourceManager : references
    ResourceManager --> ResourceWrapper : holds
    
    NFTPoolInstance --> ResourceWrapper : stores duplicated
```

---

_Diagrams created January 2026_
