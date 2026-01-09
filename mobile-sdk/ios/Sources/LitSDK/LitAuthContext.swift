import Foundation

public final class LitAuthContext {
    let handle: LitAuthContextHandle

    init(handle: LitAuthContextHandle) {
        self.handle = handle
    }

    deinit {
        lit_auth_context_destroy(handle)
    }
}
