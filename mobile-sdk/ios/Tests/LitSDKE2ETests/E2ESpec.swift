import XCTest
@testable import LitSDK

final class E2ESpec: XCTestCase {
    func testNetworkMapping() {
        XCTAssertEqual(NetworkConfig.nagaDev.rawValue, "naga-dev")
        XCTAssertEqual(NetworkConfig.fromEnv("naga-test"), .nagaTest)
    }

    func testClientInitWithRpcUrl() throws {
        let env = ProcessInfo.processInfo.environment
        let dotenv = loadDotEnv()
        let rpcUrl = env["LIT_RPC_URL"] ?? dotenv["LIT_RPC_URL"]
        guard let rpcUrl = rpcUrl?.trimmingCharacters(in: .whitespacesAndNewlines),
              !rpcUrl.isEmpty else {
            throw XCTSkip("Set LIT_RPC_URL to run client init test")
        }

        let networkValue = env["NETWORK"] ?? dotenv["NETWORK"]
        let network = NetworkConfig.fromEnv(networkValue)
        _ = try LitClient(network: network, rpcUrl: rpcUrl)
    }

    private func loadDotEnv() -> [String: String] {
        let testFile = URL(fileURLWithPath: #filePath)
        let repoRoot = testFile
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let envUrl = repoRoot.appendingPathComponent("lit-rust-sdk/.env")
        guard let contents = try? String(contentsOf: envUrl) else {
            return [:]
        }

        var values: [String: String] = [:]
        for line in contents.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty,
                  !trimmed.hasPrefix("#"),
                  let equalsIndex = trimmed.firstIndex(of: "=") else {
                continue
            }
            let key = String(trimmed[..<equalsIndex])
            let value = String(trimmed[trimmed.index(after: equalsIndex)...])
            values[key] = value
        }
        return values
    }
}
