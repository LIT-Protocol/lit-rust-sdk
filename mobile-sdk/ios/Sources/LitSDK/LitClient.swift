import Foundation

public final class LitClient {
    private let handle: LitClientHandle

    public init(network: NetworkConfig, rpcUrl: String? = nil) throws {
        var errorOut: UnsafeMutablePointer<CChar>?
        let trimmedRpc = rpcUrl?.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedRpc = (trimmedRpc?.isEmpty == false) ? trimmedRpc : (network.defaultRpcUrl.isEmpty ? nil : network.defaultRpcUrl)
        let handle = network.rawValue.withCString { networkCString in
            if let resolvedRpc = resolvedRpc {
                return resolvedRpc.withCString { rpcCString in
                    lit_client_create(networkCString, rpcCString, &errorOut)
                }
            }
            return lit_client_create(networkCString, nil, &errorOut)
        }

        guard let handle = handle else {
            let errorMessage = getFFIError(&errorOut) ?? "Failed to create LitClient"
            throw LitSDKError.ffiError(errorMessage)
        }

        self.handle = handle
    }

    deinit {
        lit_client_destroy(handle)
    }

    public func createEoaAuthContext(
        pkpPublicKey: String,
        eoaPrivateKey: String,
        expirationMinutes: UInt32 = 30
    ) throws -> LitAuthContext {
        let trimmedPkp = pkpPublicKey.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedEoa = eoaPrivateKey.trimmingCharacters(in: .whitespacesAndNewlines)

        guard !trimmedPkp.isEmpty else {
            throw LitSDKError.ffiError("PKP public key is required.")
        }
        guard !trimmedEoa.isEmpty else {
            throw LitSDKError.ffiError("EOA private key is required.")
        }

        var errorOut: UnsafeMutablePointer<CChar>?
        let authHandle = trimmedPkp.withCString { pkpCString in
            trimmedEoa.withCString { eoaCString in
                lit_auth_context_create(handle, pkpCString, eoaCString, expirationMinutes, &errorOut)
            }
        }

        guard let authHandle = authHandle else {
            let errorMessage = getFFIError(&errorOut) ?? "Failed to create auth context"
            throw LitSDKError.ffiError(errorMessage)
        }

        return LitAuthContext(handle: authHandle)
    }

    public static func eoaAddress(fromPrivateKey privateKey: String) throws -> String {
        let trimmed = privateKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw LitSDKError.ffiError("EOA private key is required.")
        }

        var resultOut: UnsafeMutablePointer<CChar>?
        var errorOut: UnsafeMutablePointer<CChar>?

        let status = trimmed.withCString { keyCString in
            lit_eoa_address_from_private_key(keyCString, &resultOut, &errorOut)
        }

        guard status == 0 else {
            let errorMessage = getFFIError(&errorOut) ?? "Failed to derive EOA address"
            throw LitSDKError.ffiError(errorMessage)
        }

        guard let address = getFFIResult(&resultOut) else {
            throw LitSDKError.ffiError("Failed to read EOA address result")
        }

        return address
    }

    public func viewPkpsByAddress(
        ownerAddress: String,
        limit: UInt32 = 5,
        offset: UInt32 = 0
    ) throws -> LitPkpList {
        let trimmed = ownerAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw LitSDKError.ffiError("Owner address is required.")
        }

        var resultOut: UnsafeMutablePointer<CChar>?
        var errorOut: UnsafeMutablePointer<CChar>?

        let status = trimmed.withCString { addressCString in
            lit_view_pkps_by_address(handle, addressCString, limit, offset, &resultOut, &errorOut)
        }

        guard status == 0 else {
            let errorMessage = getFFIError(&errorOut) ?? "Failed to fetch PKPs"
            throw LitSDKError.ffiError(errorMessage)
        }

        guard let jsonString = getFFIResult(&resultOut) else {
            throw LitSDKError.ffiError("Failed to read PKP list result")
        }

        let decoder = JSONDecoder()
        guard let data = jsonString.data(using: .utf8) else {
            throw LitSDKError.ffiError("Failed to decode PKP list result")
        }
        return try decoder.decode(LitPkpList.self, from: data)
    }

    public func mintPkpWithEoa(privateKey: String) throws -> LitMintPkpResult {
        let trimmed = privateKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw LitSDKError.ffiError("EOA private key is required.")
        }

        var resultOut: UnsafeMutablePointer<CChar>?
        var errorOut: UnsafeMutablePointer<CChar>?

        let status = trimmed.withCString { keyCString in
            lit_mint_pkp_with_eoa(handle, keyCString, &resultOut, &errorOut)
        }

        guard status == 0 else {
            let errorMessage = getFFIError(&errorOut) ?? "Failed to mint PKP"
            throw LitSDKError.ffiError(errorMessage)
        }

        guard let jsonString = getFFIResult(&resultOut) else {
            throw LitSDKError.ffiError("Failed to read mint result")
        }

        let decoder = JSONDecoder()
        guard let data = jsonString.data(using: .utf8) else {
            throw LitSDKError.ffiError("Failed to decode mint result")
        }
        return try decoder.decode(LitMintPkpResult.self, from: data)
    }

    public func getBalances(forAddress address: String) throws -> LitBalances {
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw LitSDKError.ffiError("EOA address is required.")
        }

        var resultOut: UnsafeMutablePointer<CChar>?
        var errorOut: UnsafeMutablePointer<CChar>?

        let status = trimmed.withCString { addressCString in
            lit_get_balances(handle, addressCString, &resultOut, &errorOut)
        }

        guard status == 0 else {
            let errorMessage = getFFIError(&errorOut) ?? "Failed to fetch balances"
            throw LitSDKError.ffiError(errorMessage)
        }

        guard let jsonString = getFFIResult(&resultOut) else {
            throw LitSDKError.ffiError("Failed to read balances result")
        }

        let decoder = JSONDecoder()
        guard let data = jsonString.data(using: .utf8) else {
            throw LitSDKError.ffiError("Failed to decode balances result")
        }
        return try decoder.decode(LitBalances.self, from: data)
    }

    public func executeJs(
        code: String,
        jsParamsJson: String? = nil,
        authContext: LitAuthContext
    ) throws -> String {
        let trimmedCode = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedCode.isEmpty else {
            throw LitSDKError.ffiError("Lit Action code is required.")
        }

        let trimmedParams = jsParamsJson?.trimmingCharacters(in: .whitespacesAndNewlines)
        var resultOut: UnsafeMutablePointer<CChar>?
        var errorOut: UnsafeMutablePointer<CChar>?

        let status = trimmedCode.withCString { codeCString in
            if let params = trimmedParams, !params.isEmpty {
                return params.withCString { paramsCString in
                    lit_execute_js(handle, codeCString, paramsCString, authContext.handle, &resultOut, &errorOut)
                }
            }
            return lit_execute_js(handle, codeCString, nil, authContext.handle, &resultOut, &errorOut)
        }

        guard status == 0 else {
            let errorMessage = getFFIError(&errorOut) ?? "Failed to execute Lit Action"
            throw LitSDKError.ffiError(errorMessage)
        }

        guard let result = getFFIResult(&resultOut) else {
            throw LitSDKError.ffiError("Failed to read execute_js result")
        }

        return result
    }

    public func encrypt(
        plaintext: Data,
        accessControlConditionsJson: String? = nil
    ) throws -> LitEncryptResult {
        guard !plaintext.isEmpty else {
            throw LitSDKError.ffiError("Plaintext is required.")
        }

        let trimmedAcc = accessControlConditionsJson?.trimmingCharacters(in: .whitespacesAndNewlines)
        var resultOut: UnsafeMutablePointer<CChar>?
        var errorOut: UnsafeMutablePointer<CChar>?

        let status = plaintext.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.bindMemory(to: UInt8.self).baseAddress else {
                return Int32(1)
            }
            if let acc = trimmedAcc, !acc.isEmpty {
                return acc.withCString { accCString in
                    lit_encrypt(handle, baseAddress, plaintext.count, accCString, &resultOut, &errorOut)
                }
            }
            return lit_encrypt(handle, baseAddress, plaintext.count, nil, &resultOut, &errorOut)
        }

        guard status == 0 else {
            let errorMessage = getFFIError(&errorOut) ?? "Failed to encrypt data"
            throw LitSDKError.ffiError(errorMessage)
        }

        guard let jsonString = getFFIResult(&resultOut) else {
            throw LitSDKError.ffiError("Failed to read encrypt result")
        }

        let decoder = JSONDecoder()
        guard let data = jsonString.data(using: .utf8) else {
            throw LitSDKError.ffiError("Failed to decode encrypt result")
        }
        return try decoder.decode(LitEncryptResult.self, from: data)
    }

    public func encrypt(
        plaintext: String,
        accessControlConditionsJson: String? = nil
    ) throws -> LitEncryptResult {
        guard let data = plaintext.data(using: .utf8) else {
            throw LitSDKError.ffiError("Plaintext must be UTF-8 encodable.")
        }
        return try encrypt(plaintext: data, accessControlConditionsJson: accessControlConditionsJson)
    }

    public func decrypt(
        ciphertextBase64: String,
        dataHashHex: String,
        accessControlConditionsJson: String? = nil,
        chain: String,
        authContext: LitAuthContext
    ) throws -> LitDecryptResult {
        let trimmedCiphertext = ciphertextBase64.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedHash = dataHashHex.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedChain = chain.trimmingCharacters(in: .whitespacesAndNewlines)

        guard !trimmedCiphertext.isEmpty else {
            throw LitSDKError.ffiError("Ciphertext is required.")
        }
        guard !trimmedHash.isEmpty else {
            throw LitSDKError.ffiError("Data hash is required.")
        }
        guard !trimmedChain.isEmpty else {
            throw LitSDKError.ffiError("Chain is required.")
        }

        let trimmedAcc = accessControlConditionsJson?.trimmingCharacters(in: .whitespacesAndNewlines)
        var resultOut: UnsafeMutablePointer<CChar>?
        var errorOut: UnsafeMutablePointer<CChar>?

        let status = trimmedCiphertext.withCString { ciphertextCString in
            trimmedHash.withCString { hashCString in
                trimmedChain.withCString { chainCString in
                    if let acc = trimmedAcc, !acc.isEmpty {
                        return acc.withCString { accCString in
                            lit_decrypt(
                                handle,
                                ciphertextCString,
                                hashCString,
                                accCString,
                                chainCString,
                                authContext.handle,
                                &resultOut,
                                &errorOut
                            )
                        }
                    }
                    return lit_decrypt(
                        handle,
                        ciphertextCString,
                        hashCString,
                        nil,
                        chainCString,
                        authContext.handle,
                        &resultOut,
                        &errorOut
                    )
                }
            }
        }

        guard status == 0 else {
            let errorMessage = getFFIError(&errorOut) ?? "Failed to decrypt data"
            throw LitSDKError.ffiError(errorMessage)
        }

        guard let jsonString = getFFIResult(&resultOut) else {
            throw LitSDKError.ffiError("Failed to read decrypt result")
        }

        let decoder = JSONDecoder()
        guard let data = jsonString.data(using: .utf8) else {
            throw LitSDKError.ffiError("Failed to decode decrypt result")
        }
        return try decoder.decode(LitDecryptResult.self, from: data)
    }

    public func pkpSign(
        pkpPublicKey: String,
        message: Data,
        authContext: LitAuthContext
    ) throws -> String {
        let trimmedPkp = pkpPublicKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedPkp.isEmpty else {
            throw LitSDKError.ffiError("PKP public key is required.")
        }
        guard !message.isEmpty else {
            throw LitSDKError.ffiError("Message is required.")
        }

        var resultOut: UnsafeMutablePointer<CChar>?
        var errorOut: UnsafeMutablePointer<CChar>?

        let status = trimmedPkp.withCString { pkpCString in
            message.withUnsafeBytes { rawBuffer in
                guard let baseAddress = rawBuffer.bindMemory(to: UInt8.self).baseAddress else {
                    return Int32(1)
                }
                return lit_client_pkp_sign(
                    handle,
                    pkpCString,
                    baseAddress,
                    message.count,
                    authContext.handle,
                    &resultOut,
                    &errorOut
                )
            }
        }

        guard status == 0 else {
            let errorMessage = getFFIError(&errorOut) ?? "Failed to sign with PKP"
            throw LitSDKError.ffiError(errorMessage)
        }

        guard let signature = getFFIResult(&resultOut) else {
            throw LitSDKError.ffiError("Failed to read signature result")
        }

        return signature
    }

    public func pkpSign(
        pkpPublicKey: String,
        message: String,
        authContext: LitAuthContext
    ) throws -> String {
        guard let data = message.data(using: .utf8) else {
            throw LitSDKError.ffiError("Message must be UTF-8 encodable.")
        }
        return try pkpSign(pkpPublicKey: pkpPublicKey, message: data, authContext: authContext)
    }
}
