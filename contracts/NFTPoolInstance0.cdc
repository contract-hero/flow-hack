import NFTPoolInterface, NFTFactory

access(all) contract NFTPoolInstance0: NFTPoolInterface {

    access(self) var resourcePool: @[NFTFactory.ResourceWrapper]

    access(all) fun withdrawResource(account: auth(Storage) &Account): @NFTFactory.ResourceWrapper? {
        assert(account.address == self.account.address, message: "4")
        if self.resourcePool.length > 0 {
            return <- self.resourcePool.remove(at: 0)
        } else {
            return nil
        }
    }

    init(resource: @NFTFactory.ResourceWrapper) {
        self.resourcePool <- [<- resource]
    }
}