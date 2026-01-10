import Foundation

public enum NetworkConfig: String, CaseIterable {
    case nagaDev = "naga-dev"
    case nagaTest = "naga-test"
    case nagaStaging = "naga-staging"
    case nagaProto = "naga-proto"
    case naga = "naga"
    case nagaLocal = "naga-local"

    public static func fromEnv(_ value: String?) -> NetworkConfig {
        guard let value = value else {
            return .nagaDev
        }
        return NetworkConfig(rawValue: value) ?? .nagaDev
    }

    public var defaultDetails: NetworkDefaults? {
        NetworkConfig.defaults(for: self)
    }

    public var defaultRpcUrl: String {
        defaultDetails?.rpcUrl ?? ""
    }

    public struct NetworkDefaults {
        public let title: String
        public let chainId: String
        public let chainHex: String
        public let currencySymbol: String
        public let currencyDecimals: Int
        public let rpcUrl: String
    }

    private static func defaults(for network: NetworkConfig) -> NetworkDefaults? {
        switch network {
        case .naga:
            return mainnetDefaults
        case .nagaLocal:
            return nil
        default:
            return testnetDefaults
        }
    }

    private static let testnetDefaults = NetworkDefaults(
        title: "Chronicle Yellowstone (Testnet)",
        chainId: "175188",
        chainHex: "0x2ac54",
        currencySymbol: "tstLPX",
        currencyDecimals: 18,
        rpcUrl: "https://yellowstone-rpc.litprotocol.com/"
    )

    private static let mainnetDefaults = NetworkDefaults(
        title: "Lit Chain (Mainnet)",
        chainId: "175200",
        chainHex: "0x2ac60",
        currencySymbol: "LITKEY",
        currencyDecimals: 18,
        rpcUrl: "https://lit-chain-rpc.litprotocol.com"
    )
}
