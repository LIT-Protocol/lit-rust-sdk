import Foundation

public struct LitPkpData: Codable, Hashable, Identifiable {
    public let tokenId: String
    public let pubkey: String
    public let ethAddress: String

    public var id: String { pubkey }
}

public struct LitPagination: Codable, Hashable {
    public let limit: Int
    public let offset: Int
    public let total: Int
    public let hasMore: Bool
}

public struct LitPkpList: Codable, Hashable {
    public let pkps: [LitPkpData]
    public let pagination: LitPagination
}

public struct LitMintPkpResult: Codable, Hashable {
    public let txHash: String
    public let data: LitPkpData
}

public struct LitBalances: Codable, Hashable {
    public let nativeBalanceWei: String
    public let nativeBalance: String
    public let ledgerTotalWei: String
    public let ledgerTotal: String
    public let ledgerAvailableWei: String
    public let ledgerAvailable: String
}

public struct LitEncryptResult: Codable, Hashable {
    public let ciphertextBase64: String
    public let dataToEncryptHashHex: String
}

public struct LitDecryptResult: Codable, Hashable {
    public let decryptedDataBase64: String
    public let decryptedDataUtf8: String?
}
