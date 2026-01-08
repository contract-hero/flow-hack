import "NFTFactory"

access(all) contract interface NFTPoolInterface {
    access(all) fun withdrawResource(account: auth(Storage) &Account): @NFTFactory.ResourceWrapper?
}