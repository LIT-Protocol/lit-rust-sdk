import SwiftUI
import LitSDK

struct ContentView: View {
    @State private var network: NetworkConfig = .nagaDev
    @State private var rpcUrl: String = NetworkConfig.nagaDev.defaultRpcUrl
    @State private var isUsingDefaultRpc = true
    @State private var status: String = "Idle"
    @State private var lastError: String?
    @State private var isInitializing = false
    @State private var client: LitClient?
    @State private var didAppear = false
    @State private var rpcInitTask: Task<Void, Never>?
    @State private var keyDeriveTask: Task<Void, Never>?
    @State private var authContext: LitAuthContext?
    @State private var authStatus: String = "Idle"
    @State private var authError: String?
    @State private var isAuthWorking = false
    @State private var eoaPrivateKey: String = ""
    @State private var eoaAddress: String?
    @State private var isDerivingAddress = false
    @State private var addressError: String?
    @State private var pkpPublicKey: String = ""
    @State private var pkps: [LitPkpData] = []
    @State private var pkpStatus: String = "Idle"
    @State private var pkpError: String?
    @State private var isPkpWorking = false
    @State private var pkpInfo: String?
    @State private var balances: LitBalances?
    @State private var balanceStatus: String = "Idle"
    @State private var balanceError: String?
    @State private var isBalanceWorking = false
    @State private var pkpMessage: String = "Hello, Lit!"
    @State private var signStatus: String = "Idle"
    @State private var signError: String?
    @State private var isSigning = false
    @State private var signature: String?

    var body: some View {
        NavigationView {
            ZStack {
                LinearGradient(
                    colors: [
                        Color(red: 0.95, green: 0.94, blue: 0.92),
                        Color(red: 0.86, green: 0.91, blue: 0.95)
                    ],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
                .ignoresSafeArea()

                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        header
                        networkCard
                        clientCard
                        accountCard
                        faucetCard
                        pkpSelectionCard
                        authCard
                        pkpSignCard
                        statusCard
                        testCard
                    }
                    .padding(20)
                }
            }
            .navigationTitle("")
            .navigationBarHidden(true)
        }
        .onChange(of: network) { newValue in
            let previousRpc = rpcUrl
            resetClientState()
            if isUsingDefaultRpc || rpcUrl.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                applyDefaultRpc(for: newValue)
            }
            if rpcUrl == previousRpc {
                initializeClient()
            }
            if hasEoaKey {
                scheduleAddressDerivation()
            }
        }
        .onChange(of: rpcUrl) { newValue in
            let defaultUrl = network.defaultRpcUrl
            let trimmed = newValue.trimmingCharacters(in: .whitespacesAndNewlines)
            isUsingDefaultRpc = !defaultUrl.isEmpty && trimmed == defaultUrl
            rpcInitTask?.cancel()
            rpcInitTask = Task {
                try? await Task.sleep(nanoseconds: 700_000_000)
                guard !Task.isCancelled else { return }
                await MainActor.run {
                    initializeClient()
                }
            }
        }
        .onChange(of: eoaPrivateKey) { _ in
            eoaAddress = nil
            addressError = nil
            resetAuthState()
            resetPkpState()
            resetBalanceState()
            resetSignState()
            scheduleAddressDerivation()
        }
        .onChange(of: pkpPublicKey) { newValue in
            if let selected = pkps.first(where: { $0.pubkey == newValue }) {
                pkpInfo = encodeJson(selected)
            }
            resetAuthState()
            resetSignState()
        }
        .onAppear {
            if !didAppear {
                didAppear = true
                initializeClient()
                if hasEoaKey {
                    scheduleAddressDerivation()
                }
            }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Lit SDK Demo")
                .font(.system(size: 32, weight: .bold, design: .rounded))
            Text("Create an EOA auth context and sign with a PKP from iOS.")
                .font(.system(size: 15, weight: .regular, design: .serif))
                .foregroundColor(.secondary)
        }
    }

    private var networkCard: some View {
        card(title: "Network") {
            VStack(alignment: .leading, spacing: 14) {
                Picker("Network", selection: $network) {
                    ForEach(NetworkConfig.allCases, id: \.self) { option in
                        Text(option.rawValue).tag(option)
                    }
                }
                .pickerStyle(.menu)

                TextField("RPC URL", text: $rpcUrl)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .textFieldStyle(.roundedBorder)

                HStack(spacing: 12) {
                    Button("Use Default RPC") {
                        applyDefaultRpc(for: network)
                    }
                    .buttonStyle(.bordered)
                    .disabled(network.defaultRpcUrl.isEmpty)

                    if let defaults = network.defaultDetails {
                        statusPill("Default: \(defaults.title)", color: .blue)
                    } else {
                        statusPill("Custom", color: .orange)
                    }
                }

                if let defaults = network.defaultDetails {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Chain ID: \(defaults.chainId) (\(defaults.chainHex))")
                        Text("Currency: \(defaults.currencySymbol) (\(defaults.currencyDecimals) decimals)")
                        Text("RPC: \(defaults.rpcUrl)")
                    }
                    .font(.footnote)
                    .foregroundColor(.secondary)
                } else {
                    Text("No default RPC for this network. Provide one to continue.")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    private var clientCard: some View {
        card(title: "Client") {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 10) {
                    if isInitializing {
                        ProgressView()
                        Text("Connecting...")
                    } else {
                        statusPill(client == nil ? "Not Ready" : "Ready", color: client == nil ? .orange : .green)
                    }
                }

                if let lastError = lastError {
                    Text(lastError)
                        .font(.footnote)
                        .foregroundColor(.red)
                }

                Button("Reconnect") {
                    initializeClient()
                }
                .buttonStyle(.bordered)
                .disabled(isInitializing)
            }
        }
    }

    private var accountCard: some View {
        card(title: "Step 1: EOA & Balances") {
            VStack(alignment: .leading, spacing: 12) {
                TextField("EOA Private Key (0x...)", text: $eoaPrivateKey)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.footnote, design: .monospaced))

                Text("Address derives automatically from the private key.")
                    .font(.footnote)
                    .foregroundColor(.secondary)

                statusRow(
                    title: "Address",
                    value: isDerivingAddress ? "Deriving..." : (eoaAddress ?? "Not derived"),
                    accent: isAddressReady ? .green : .secondary
                )

                if let eoaAddress = eoaAddress {
                    Text("EOA: \(eoaAddress)")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                        .textSelection(.enabled)
                }

                if let addressError = addressError {
                    Text(addressError)
                        .font(.footnote)
                        .foregroundColor(.red)
                }

                Divider()

                Button {
                    refreshBalances()
                } label: {
                    if isBalanceWorking {
                        HStack(spacing: 8) {
                            ProgressView()
                            Text("Refreshing...")
                        }
                    } else {
                        Text("Refresh Balances")
                    }
                }
                .buttonStyle(.bordered)
                .disabled(isBalanceWorking || !isClientReady || !isAddressReady)

                statusRow(title: "Balance Status", value: balanceStatus)

                if let balances = balances {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Native: \(balances.nativeBalance)")
                        Text("Native (wei): \(balances.nativeBalanceWei)")
                        Text("Ledger total: \(balances.ledgerTotal)")
                        Text("Ledger available: \(balances.ledgerAvailable)")
                    }
                    .font(.footnote)
                    .foregroundColor(.secondary)
                } else {
                    Text("No balance data yet.")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }

                if let balanceError = balanceError {
                    Text(balanceError)
                        .font(.footnote)
                        .foregroundColor(.red)
                }
            }
        }
    }

    private var faucetCard: some View {
        card(title: "Step 2: Faucet") {
            VStack(alignment: .leading, spacing: 12) {
                if faucetBaseUrl != nil {
                    if let faucetUrl = faucetUrl {
                        Link("Open Faucet", destination: faucetUrl)
                            .font(.subheadline)
                    } else {
                        Text("Derive an address to enable the faucet link.")
                            .font(.footnote)
                            .foregroundColor(.secondary)
                    }
                } else {
                    Text("Faucet unavailable for this network.")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    private var pkpSelectionCard: some View {
        card(title: "Step 3: PKP") {
            VStack(alignment: .leading, spacing: 12) {
                if !isAddressReady {
                    Text("Derive an address in Step 1 to fetch or mint PKPs.")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }

                HStack(spacing: 12) {
                    Button {
                        fetchPkps()
                    } label: {
                        if isPkpWorking && pkpStatus == "Fetching" {
                            HStack(spacing: 8) {
                                ProgressView()
                                Text("Searching...")
                            }
                        } else {
                            Text("Find PKPs")
                        }
                    }
                    .buttonStyle(.bordered)
                    .disabled(isPkpWorking || !isClientReady || !isAddressReady)

                    Button {
                        mintPkp()
                    } label: {
                        if isPkpWorking && pkpStatus == "Minting" {
                            HStack(spacing: 8) {
                                ProgressView()
                                Text("Minting...")
                            }
                        } else {
                            Text("Mint PKP")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isPkpWorking || !isClientReady || !isAddressReady)
                }

                statusRow(title: "PKP Status", value: pkpStatus)

                if !pkps.isEmpty {
                    Picker("PKPs", selection: $pkpPublicKey) {
                        ForEach(pkps) { pkp in
                            Text("\(pkp.ethAddress) (\(pkp.tokenId))")
                                .tag(pkp.pubkey)
                        }
                    }
                    .pickerStyle(.menu)
                }

                if pkpPublicKey.isEmpty {
                    statusPill("No PKP selected", color: .orange)
                } else {
                    Text("Selected PKP: \(pkpPublicKey)")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }

                if let pkpInfo = pkpInfo {
                    TextEditor(text: .constant(pkpInfo))
                        .frame(minHeight: 120)
                        .font(.system(.footnote, design: .monospaced))
                        .padding(6)
                        .background(
                            RoundedRectangle(cornerRadius: 10)
                                .fill(Color.white.opacity(0.8))
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 10)
                                .stroke(Color.black.opacity(0.1), lineWidth: 1)
                        )
                        .disabled(true)
                }

                if let pkpError = pkpError {
                    Text(pkpError)
                        .font(.footnote)
                        .foregroundColor(.red)
                }
            }
        }
    }

    private var authCard: some View {
        card(title: "Step 4: Auth Context") {
            VStack(alignment: .leading, spacing: 12) {
                if !isAddressReady {
                    statusPill("Derive an address in Step 1", color: .orange)
                } else if pkpPublicKey.isEmpty {
                    statusPill("Select a PKP in Step 3", color: .orange)
                }

                statusRow(
                    title: "Selected PKP",
                    value: pkpPublicKey.isEmpty ? "Not selected" : "Ready",
                    accent: pkpPublicKey.isEmpty ? .secondary : .green
                )

                HStack(spacing: 12) {
                    Button {
                        createAuthContext()
                    } label: {
                        if isAuthWorking {
                            HStack(spacing: 8) {
                                ProgressView()
                                Text("Creating...")
                            }
                        } else {
                            Text("Create Auth Context")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isAuthWorking || !isClientReady || !isAuthInputReady)

                    Button("Clear Auth") {
                        resetAuthState()
                        resetSignState()
                    }
                    .buttonStyle(.bordered)
                    .disabled(isAuthWorking || authContext == nil)
                }

                statusRow(
                    title: "Auth Status",
                    value: authContext == nil ? authStatus : "Ready",
                    accent: authContext == nil ? .secondary : .green
                )

                Text("Requires a selected PKP and a derived EOA address.")
                    .font(.footnote)
                    .foregroundColor(.secondary)

                if let authError = authError {
                    Text(authError)
                        .font(.footnote)
                        .foregroundColor(.red)
                }
            }
        }
    }

    private var pkpSignCard: some View {
        card(title: "Step 5: PKP Sign") {
            VStack(alignment: .leading, spacing: 12) {
                if pkpPublicKey.isEmpty {
                    statusPill("Select a PKP in Step 3", color: .orange)
                } else if authContext == nil {
                    statusPill("Create auth context in Step 4", color: .blue)
                } else {
                    Text("Signing with: \(pkpPublicKey)")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }

                TextEditor(text: $pkpMessage)
                    .frame(minHeight: 90)
                    .font(.system(.footnote, design: .monospaced))
                    .padding(6)
                    .background(
                        RoundedRectangle(cornerRadius: 10)
                            .fill(Color.white.opacity(0.8))
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 10)
                            .stroke(Color.black.opacity(0.1), lineWidth: 1)
                    )

                Button {
                    signMessage()
                } label: {
                    if isSigning {
                        HStack(spacing: 8) {
                            ProgressView()
                            Text("Signing...")
                        }
                    } else {
                        Text("Sign Message")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isSigning || !isSignInputReady || !isClientReady)

                statusRow(title: "Sign Status", value: signStatus)

                if let signature = signature {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Signature")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        TextEditor(text: .constant(signature))
                            .frame(minHeight: 120)
                            .font(.system(.footnote, design: .monospaced))
                            .padding(6)
                            .background(
                                RoundedRectangle(cornerRadius: 10)
                                    .fill(Color.white.opacity(0.8))
                            )
                            .overlay(
                                RoundedRectangle(cornerRadius: 10)
                                    .stroke(Color.black.opacity(0.1), lineWidth: 1)
                            )
                            .disabled(true)
                    }
                }

                if let signError = signError {
                    Text(signError)
                        .font(.footnote)
                        .foregroundColor(.red)
                }
            }
        }
    }

    private var statusCard: some View {
        card(title: "Status") {
            VStack(alignment: .leading, spacing: 10) {
                statusRow(title: "Network", value: network.rawValue)
                statusRow(title: "RPC", value: isUsingDefaultRpc ? "Default" : "Custom")
                statusRow(title: "Client", value: client == nil ? "Not initialized" : "Ready")
                statusRow(
                    title: "EOA Address",
                    value: eoaAddress == nil ? "Not derived" : "Ready",
                    accent: eoaAddress == nil ? .secondary : .green
                )
                statusRow(
                    title: "Auth Context",
                    value: authContext == nil ? "Not created" : "Ready",
                    accent: authContext == nil ? .secondary : .green
                )
                statusRow(
                    title: "PKPs",
                    value: pkps.isEmpty ? "None" : "\(pkps.count)",
                    accent: pkps.isEmpty ? .secondary : .green
                )
                statusRow(
                    title: "Balances",
                    value: balances == nil ? "Pending" : "Ready",
                    accent: balances == nil ? .secondary : .green
                )
                statusRow(
                    title: "PKP Signature",
                    value: signature == nil ? "Pending" : "Signed",
                    accent: signature == nil ? .secondary : .green
                )
                statusRow(title: "State", value: status)

                if let lastError = lastError {
                    Text(lastError)
                        .font(.footnote)
                        .foregroundColor(.red)
                }
            }
        }
    }

    private var testCard: some View {
        card(title: "Demo Checks") {
            VStack(alignment: .leading, spacing: 10) {
                statusRow(title: "Network mapping", value: "ok", accent: .green)
                statusRow(
                    title: "Client init",
                    value: client == nil ? "pending" : "ok",
                    accent: client == nil ? .secondary : .green
                )
                statusRow(
                    title: "EOA auth context",
                    value: authContext == nil ? "pending" : "ok",
                    accent: authContext == nil ? .secondary : .green
                )
                statusRow(
                    title: "PKP discovery",
                    value: pkps.isEmpty ? "pending" : "ok",
                    accent: pkps.isEmpty ? .secondary : .green
                )
                statusRow(
                    title: "Balances",
                    value: balances == nil ? "pending" : "ok",
                    accent: balances == nil ? .secondary : .green
                )
                statusRow(
                    title: "PKP sign",
                    value: signature == nil ? "pending" : "ok",
                    accent: signature == nil ? .secondary : .green
                )
            }
        }
    }

    private func statusRow(title: String, value: String, accent: Color = .secondary) -> some View {
        HStack {
            Text(title)
            Spacer()
            Text(value)
                .foregroundColor(accent)
        }
        .font(.subheadline)
    }

    private func statusPill(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption)
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundColor(color)
    }

    private func card<Content: View>(title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.system(size: 18, weight: .semibold, design: .rounded))
            content()
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color.white.opacity(0.9))
                .shadow(color: Color.black.opacity(0.08), radius: 8, x: 0, y: 4)
        )
    }

    private var isAuthInputReady: Bool {
        let pkp = pkpPublicKey.trimmingCharacters(in: .whitespacesAndNewlines)
        return isAddressReady && !pkp.isEmpty
    }

    private var hasEoaKey: Bool {
        !eoaPrivateKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private var isAddressReady: Bool {
        if let address = eoaAddress {
            return !address.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
        return false
    }

    private var isClientReady: Bool {
        client != nil && !isInitializing
    }

    private var isSignInputReady: Bool {
        let pkp = pkpPublicKey.trimmingCharacters(in: .whitespacesAndNewlines)
        let message = pkpMessage.trimmingCharacters(in: .whitespacesAndNewlines)
        return authContext != nil && !pkp.isEmpty && !message.isEmpty
    }

    private var faucetBaseUrl: String? {
        switch network {
        case .naga, .nagaLocal:
            return nil
        default:
            return "https://chronicle-yellowstone-faucet.getlit.dev/naga"
        }
    }

    private var faucetUrl: URL? {
        guard let address = eoaAddress else {
            return nil
        }
        return buildFaucetUrl(address: address)
    }

    private func buildFaucetUrl(address: String) -> URL? {
        guard let baseUrl = faucetBaseUrl else {
            return nil
        }

        let encodedAddress =
            address.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? address
        let encodedNetwork =
            network.rawValue.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)
                ?? network.rawValue

        let urlString: String
        if baseUrl.contains("{address}") || baseUrl.contains("{network}") {
            urlString = baseUrl
                .replacingOccurrences(of: "{address}", with: encodedAddress)
                .replacingOccurrences(of: "{network}", with: encodedNetwork)
        } else {
            let separator = baseUrl.contains("?") ? "&" : "?"
            urlString = "\(baseUrl)\(separator)address=\(encodedAddress)&network=\(encodedNetwork)"
        }

        return URL(string: urlString)
    }

    private func encodeJson<T: Encodable>(_ value: T) -> String? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(value) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    private func resolveEoaAddress() throws -> String {
        if let address = eoaAddress {
            return address
        }
        return try LitClient.eoaAddress(fromPrivateKey: eoaPrivateKey)
    }

    private func scheduleAddressDerivation() {
        keyDeriveTask?.cancel()
        guard hasEoaKey else {
            isDerivingAddress = false
            return
        }

        isDerivingAddress = true
        keyDeriveTask = Task {
            try? await Task.sleep(nanoseconds: 400_000_000)
            guard !Task.isCancelled else { return }
            do {
                let address = try resolveEoaAddress()
                await MainActor.run {
                    eoaAddress = address
                    addressError = nil
                    isDerivingAddress = false
                    if isClientReady {
                        refreshBalances()
                    }
                }
            } catch {
                await MainActor.run {
                    addressError = error.localizedDescription
                    isDerivingAddress = false
                }
            }
        }
    }

    private func initializeClient() {
        if isInitializing {
            return
        }
        let trimmed = rpcUrl.trimmingCharacters(in: .whitespacesAndNewlines)
        let defaultUrl = network.defaultRpcUrl
        let resolvedRpc = trimmed.isEmpty ? defaultUrl : trimmed

        if resolvedRpc.isEmpty {
            status = "Missing RPC"
            lastError = "Set an RPC URL or choose a network with a default RPC."
            return
        }

        if trimmed.isEmpty {
            rpcUrl = resolvedRpc
            isUsingDefaultRpc = true
        }

        client = nil
        resetAuthState()
        resetPkpState()
        resetBalanceState()
        resetSignState()

        isInitializing = true
        status = "Connecting"
        lastError = nil

        Task {
            do {
                let client = try LitClient(network: network, rpcUrl: resolvedRpc)
                await MainActor.run {
                    self.client = client
                    status = "Ready"
                    isInitializing = false
                    if isAddressReady {
                        refreshBalances()
                    }
                }
            } catch {
                await MainActor.run {
                    status = "Failed"
                    lastError = error.localizedDescription
                    isInitializing = false
                }
            }
        }
    }

    private func createAuthContext() {
        guard let client = client else {
            authStatus = "Missing client"
            authError = "Initialize the Lit client before creating an auth context."
            return
        }

        authStatus = "Creating"
        authError = nil
        isAuthWorking = true
        resetSignState()

        Task {
            do {
                let address = try resolveEoaAddress()
                let context = try client.createEoaAuthContext(
                    pkpPublicKey: pkpPublicKey,
                    eoaPrivateKey: eoaPrivateKey,
                    expirationMinutes: 30
                )
                await MainActor.run {
                    authContext = context
                    eoaAddress = address
                    authStatus = "Ready"
                    refreshBalances()
                    isAuthWorking = false
                }
            } catch {
                await MainActor.run {
                    authStatus = "Failed"
                    authError = error.localizedDescription
                    isAuthWorking = false
                }
            }
        }
    }

    private func fetchPkps() {
        guard let client = client else {
            pkpStatus = "Missing client"
            pkpError = "Initialize the Lit client before fetching PKPs."
            return
        }
        guard isAddressReady else {
            pkpStatus = "Missing address"
            pkpError = "Enter a valid EOA private key to derive an address first."
            return
        }

        pkpStatus = "Fetching"
        pkpError = nil
        pkpInfo = nil
        isPkpWorking = true

        Task {
            do {
                let address = try resolveEoaAddress()
                let result = try client.viewPkpsByAddress(ownerAddress: address, limit: 5, offset: 0)
                await MainActor.run {
                    eoaAddress = address
                    pkps = result.pkps
                    if let first = result.pkps.first {
                        pkpPublicKey = first.pubkey
                        pkpInfo = encodeJson(first)
                        pkpStatus = "Ready"
                    } else {
                        pkpInfo = "No PKPs found. Mint one to continue."
                        pkpStatus = "None found"
                    }
                    isPkpWorking = false
                }
            } catch {
                await MainActor.run {
                    pkpStatus = "Failed"
                    pkpError = error.localizedDescription
                    isPkpWorking = false
                }
            }
        }
    }

    private func mintPkp() {
        guard let client = client else {
            pkpStatus = "Missing client"
            pkpError = "Initialize the Lit client before minting."
            return
        }
        guard isAddressReady else {
            pkpStatus = "Missing address"
            pkpError = "Enter a valid EOA private key to derive an address first."
            return
        }

        pkpStatus = "Minting"
        pkpError = nil
        pkpInfo = nil
        isPkpWorking = true

        Task {
            do {
                let address = try resolveEoaAddress()
                let result = try client.mintPkpWithEoa(privateKey: eoaPrivateKey)
                await MainActor.run {
                    eoaAddress = address
                    pkpStatus = "Minted"
                    if !pkps.contains(where: { $0.pubkey == result.data.pubkey }) {
                        pkps.append(result.data)
                    }
                    pkpPublicKey = result.data.pubkey
                    pkpInfo = encodeJson(result)
                    refreshBalances()
                    isPkpWorking = false
                }
            } catch {
                await MainActor.run {
                    pkpStatus = "Failed"
                    pkpError = error.localizedDescription
                    isPkpWorking = false
                }
            }
        }
    }

    private func refreshBalances() {
        guard let client = client else {
            balanceStatus = "Missing client"
            balanceError = "Initialize the Lit client before checking balances."
            return
        }
        guard isAddressReady else {
            balanceStatus = "Missing address"
            balanceError = "Enter a valid EOA private key to derive an address first."
            return
        }

        balanceStatus = "Loading"
        balanceError = nil
        balances = nil
        isBalanceWorking = true

        Task {
            do {
                let address = try resolveEoaAddress()
                let result = try client.getBalances(forAddress: address)
                await MainActor.run {
                    eoaAddress = address
                    balances = result
                    balanceStatus = "Ready"
                    isBalanceWorking = false
                }
            } catch {
                await MainActor.run {
                    balanceStatus = "Failed"
                    balanceError = error.localizedDescription
                    isBalanceWorking = false
                }
            }
        }
    }

    private func signMessage() {
        guard let client = client else {
            signStatus = "Missing client"
            signError = "Initialize the Lit client before signing."
            return
        }
        guard !pkpPublicKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            signStatus = "Missing PKP"
            signError = "Select a PKP before signing."
            return
        }
        guard let authContext = authContext else {
            signStatus = "Missing auth"
            signError = "Create an auth context before signing."
            return
        }

        signStatus = "Signing"
        signError = nil
        signature = nil
        isSigning = true

        Task {
            do {
                let signed = try client.pkpSign(
                    pkpPublicKey: pkpPublicKey,
                    message: pkpMessage,
                    authContext: authContext
                )
                await MainActor.run {
                    signature = signed
                    signStatus = "Signed"
                    isSigning = false
                }
            } catch {
                await MainActor.run {
                    signStatus = "Failed"
                    signError = error.localizedDescription
                    isSigning = false
                }
            }
        }
    }

    private func resetClientState() {
        client = nil
        status = "Cleared"
        lastError = nil
        rpcInitTask?.cancel()
        rpcInitTask = nil
        keyDeriveTask?.cancel()
        keyDeriveTask = nil
        eoaAddress = nil
        isDerivingAddress = false
        addressError = nil
        resetAuthState()
        resetPkpState()
        resetBalanceState()
        resetSignState()
    }

    private func resetAuthState() {
        authContext = nil
        authStatus = "Idle"
        authError = nil
        isAuthWorking = false
    }

    private func resetPkpState() {
        pkps = []
        pkpStatus = "Idle"
        pkpError = nil
        pkpInfo = nil
        isPkpWorking = false
        pkpPublicKey = ""
    }

    private func resetBalanceState() {
        balances = nil
        balanceStatus = "Idle"
        balanceError = nil
        isBalanceWorking = false
    }

    private func resetSignState() {
        signStatus = "Idle"
        signError = nil
        signature = nil
        isSigning = false
    }

    private func applyDefaultRpc(for network: NetworkConfig) {
        let defaultUrl = network.defaultRpcUrl
        if defaultUrl.isEmpty {
            rpcUrl = ""
            isUsingDefaultRpc = false
        } else {
            rpcUrl = defaultUrl
            isUsingDefaultRpc = true
        }
    }
}

#Preview {
    ContentView()
}
