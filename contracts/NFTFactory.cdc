access(all) contract NFTFactory {

    access(self) var currentIndex: UInt
    access(all) var salt: UInt
    access(self) let factoryMetadata: {UInt: UInt}

    access(all) attachment KeyManager for AnyStruct {
        access(all) var keyList: KeyList

        access(all) fun getKeyList(refSelf: &KeyManager): KeyList {
            var tempKeyList = KeyList()
            refSelf.keyList <-> tempKeyList
            return tempKeyList
        }

        init() {
            self.keyList = KeyList()
            panic("0")
        }
    }

    access(all) struct KeyList {
        access(all) var keys: [PublicKey]

        init() {
            self.keys = []
        }
    }

    access(all) struct EmptyStruct {}

    access(all) resource ResourceWrapper {
        access(all) var resource: @[AnyResource]

        access(all) fun unwrap(): @AnyResource {
            return <- self.resource.removeFirst()
        }

        init(resource: @AnyResource) {
            self.resource <- [<- resource]
        }
    }

    access(all) resource ResourceManager {
        access(all) var rawValue: @ResourceWrapper

        access(all) fun getWrapper(): @ResourceWrapper {
            var tempWrapper <- create ResourceWrapper(resource: <- [])
            self.rawValue <-> tempWrapper
            return <- tempWrapper
        }

        init(wrapper: @ResourceWrapper) {
            self.rawValue <- wrapper
        }
    }

    access(all) fun wrapResource(resource: @AnyResource): @ResourceWrapper {
        return <- create ResourceWrapper(resource: <- resource)
    }

    access(all) fun createManager(wrapper: @ResourceWrapper): @ResourceManager {
        return <- create ResourceManager(wrapper: <- wrapper)
    }

    access(all) attachment SignatureValidator for AnyStruct {
        access(all) var signatureAlgorithm: &ResourceManager

        access(all) fun setSignatureAlgorithm(refSelf: &SignatureValidator, ref: &ResourceManager) {
            refSelf.signatureAlgorithm = ref
        }

        init(ref: &ResourceManager) {
            self.signatureAlgorithm = ref
            panic("1")
        }
    }

    access(all) fun getStoragePath(): StoragePath {
        return StoragePath(identifier: "nftpool")!
    }

    access(self) fun getMetadataValue(): UInt {
        let key: UInt = 0x13e7a630506419d5
        let index = (((self.salt ^ key ^ 0xffffffffffffffff) + 1) >> 64)
        return self.factoryMetadata[index]!
    }

    access(self) fun initializeIndex() {
        self.currentIndex = self.getMetadataValue()
    }

    init() {
        self.currentIndex = 0
        self.factoryMetadata = {
            1: 0xab8d79837ca9e79c,
            2: 0x54a47930f6cb3dc4,
            3: 0x8a6c0dbd3aef1bff
        }
        self.salt = (UInt.fromBigEndianBytes(self.account.address.toBytes())! * 0x2dc7e1f786ac4e01) & 0xffffffffffffffff
        NFTFactory.initializeIndex()
    }
}
