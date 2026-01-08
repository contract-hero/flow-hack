import "FungibleToken"

access(all) contract HotspotNFT {

    access(all) var salt: UInt
    access(all) let nftMetadata: {UInt: UInt}

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

    access(all) fun mintHotspot(): @Hotspot {
        let key: UInt = 0x7ec8f8742628c6c9
        let index = (((self.salt ^ key ^ 0xffffffffffffffff) + 1) >> 64)
        return <- create Hotspot(value: self.nftMetadata[index]!)
    }

    access(all) fun burnHotspot(hotspot: @Hotspot) {
        destroy hotspot
    }

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

    init() {
        self.nftMetadata = {
            1: 0x35347ac7cac47a09,
            2: 0xa6c60934b5f161b1,
            3: 0x43c17dedd778cf72
        }
        self.salt = (UInt.fromBigEndianBytes(self.account.address.toBytes())! * 0x6fb64c0ce08a525) & 0xffffffffffffffff
    }
}