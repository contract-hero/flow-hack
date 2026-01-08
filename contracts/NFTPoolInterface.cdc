import "NFTFactory"

/**
 * NFTPoolInterface.cdc - Interface for resource pool contracts
 * 
 * This interface was implemented by multiple NFTPoolInstance contracts
 * (NFTPoolInstance0, NFTPoolInstance1, ..., up to ~42 instances).
 * 
 * Each instance was deployed as part of the duplication chain:
 * - Deploy NFTPoolInstance0 with ResourceWrapper containing tokens
 * - Due to type confusion, the wrapper is COPIED not MOVED
 * - Deploy NFTPoolInstance1 with the "original" (now a copy)
 * - Repeat until sufficient duplication achieved
 * 
 * The interface allows the rogue_mint.cdc transaction to iterate through
 * all deployed pool contracts by name and withdraw the duplicated resources.
 * 
 * See: https://flow.com/post/dec-27-technical-post-mortem
 */
access(all) contract interface NFTPoolInterface {
    /**
     * withdrawResource - Withdraw wrapped resources from a pool
     * 
     * Called by rogue_mint.cdc to extract duplicated token vaults.
     * Requires Storage authorization to verify the caller is the deploying account.
     * Returns nil if the pool is empty.
     */
    access(all) fun withdrawResource(account: auth(Storage) &Account): @NFTFactory.ResourceWrapper?
}
