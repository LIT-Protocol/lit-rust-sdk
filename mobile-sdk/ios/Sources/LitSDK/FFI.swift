import Foundation

public typealias LitClientHandle = OpaquePointer
public typealias LitAuthContextHandle = OpaquePointer

@_silgen_name("lit_client_create")
func lit_client_create(
    _ networkName: UnsafePointer<CChar>,
    _ rpcUrl: UnsafePointer<CChar>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> LitClientHandle?

@_silgen_name("lit_client_destroy")
func lit_client_destroy(_ handle: LitClientHandle)

@_silgen_name("lit_free_string")
func lit_free_string(_ s: UnsafeMutablePointer<CChar>?)

@_silgen_name("lit_eoa_address_from_private_key")
func lit_eoa_address_from_private_key(
    _ eoaPrivateKey: UnsafePointer<CChar>,
    _ resultOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32

@_silgen_name("lit_auth_context_create")
func lit_auth_context_create(
    _ clientHandle: LitClientHandle,
    _ pkpPublicKey: UnsafePointer<CChar>,
    _ eoaPrivateKey: UnsafePointer<CChar>,
    _ expirationMinutes: UInt32,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> LitAuthContextHandle?

@_silgen_name("lit_auth_context_destroy")
func lit_auth_context_destroy(_ handle: LitAuthContextHandle)

@_silgen_name("lit_client_pkp_sign")
func lit_client_pkp_sign(
    _ clientHandle: LitClientHandle,
    _ pkpPublicKey: UnsafePointer<CChar>,
    _ messagePtr: UnsafePointer<UInt8>,
    _ messageLen: Int,
    _ authContextHandle: LitAuthContextHandle,
    _ resultOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32

@_silgen_name("lit_view_pkps_by_address")
func lit_view_pkps_by_address(
    _ clientHandle: LitClientHandle,
    _ eoaAddress: UnsafePointer<CChar>,
    _ limit: UInt32,
    _ offset: UInt32,
    _ resultOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32

@_silgen_name("lit_mint_pkp_with_eoa")
func lit_mint_pkp_with_eoa(
    _ clientHandle: LitClientHandle,
    _ eoaPrivateKey: UnsafePointer<CChar>,
    _ resultOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32

@_silgen_name("lit_get_balances")
func lit_get_balances(
    _ clientHandle: LitClientHandle,
    _ eoaAddress: UnsafePointer<CChar>,
    _ resultOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32

@_silgen_name("lit_execute_js")
func lit_execute_js(
    _ clientHandle: LitClientHandle,
    _ code: UnsafePointer<CChar>,
    _ jsParamsJson: UnsafePointer<CChar>?,
    _ authContextHandle: LitAuthContextHandle,
    _ resultOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32

@_silgen_name("lit_encrypt")
func lit_encrypt(
    _ clientHandle: LitClientHandle,
    _ plaintextPtr: UnsafePointer<UInt8>,
    _ plaintextLen: Int,
    _ accessControlJson: UnsafePointer<CChar>?,
    _ resultOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32

@_silgen_name("lit_decrypt")
func lit_decrypt(
    _ clientHandle: LitClientHandle,
    _ ciphertextBase64: UnsafePointer<CChar>,
    _ dataHashHex: UnsafePointer<CChar>,
    _ accessControlJson: UnsafePointer<CChar>?,
    _ chain: UnsafePointer<CChar>,
    _ authContextHandle: LitAuthContextHandle,
    _ resultOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32

func getFFIError(_ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> String? {
    guard let errorOut = errorOut, let errorPtr = errorOut.pointee else {
        return nil
    }
    let errorString = String(cString: errorPtr)
    lit_free_string(errorPtr)
    return errorString
}

func getFFIResult(_ resultOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> String? {
    guard let resultOut = resultOut, let resultPtr = resultOut.pointee else {
        return nil
    }
    let resultString = String(cString: resultPtr)
    lit_free_string(resultPtr)
    return resultString
}
