import Foundation

public enum LitSDKError: Error, CustomStringConvertible {
    case ffiError(String)

    public var description: String {
        switch self {
        case .ffiError(let message):
            return message
        }
    }
}
