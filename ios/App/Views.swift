import SwiftUI

let jaceGreen = Color(red: 0.239, green: 0.863, blue: 0.518)

@main
struct JacePasswordsApp: App {
    @StateObject private var model = Model()
    @Environment(\.scenePhase) private var phase
    var body: some Scene {
        WindowGroup {
            RootView().environmentObject(model).tint(jaceGreen)
                .task { await model.autoOpen(); await model.sync(); await model.checkUpdates() }
                .onChange(of: phase) { p in if p == .active { model.checkAutoLock() } }
        }
    }
}

struct RootView: View {
    @EnvironmentObject var model: Model
    var body: some View {
        let _ = model.tick
        Group {
            if !model.vault.exists { StartView() }
            else if !model.vault.unlocked {
                let f = model.vault.file()
                UnlockView(restore: false, keyMode: Vault.keyMode(f), needsSecretKey: Vault.usesSecretKey(f) && DeviceStore.load()["secretKey"] == nil)
            } else { HomeView() }
        }
    }
}

struct LogoHeader: View {
    let title: String; var subtitle: String? = nil
    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: "lock.fill").font(.system(size: 30, weight: .bold)).foregroundColor(Color(red: 0.05, green: 0.08, blue: 0.06))
                .frame(width: 64, height: 64).background(jaceGreen).clipShape(RoundedRectangle(cornerRadius: 18))
            Text(title).font(.title2.bold()).multilineTextAlignment(.center)
            if let subtitle { Text(subtitle).foregroundColor(.secondary).multilineTextAlignment(.center) }
        }.frame(maxWidth: .infinity)
    }
}

// MARK: first launch
struct StartView: View {
    @EnvironmentObject var model: Model
    @State private var remote: [String: Any]?
    @State private var checked = false
    @State private var creating = false
    @State private var error: String?
    var body: some View {
        if model.signedIn, let remote {
            UnlockView(restore: true, keyMode: Vault.keyMode(remote), needsSecretKey: Vault.usesSecretKey(remote))
        } else if creating {
            CreateView(onBack: { creating = false })
        } else {
            ScrollView {
                VStack(spacing: 16) {
                    LogoHeader(title: "Every password, card and code. One vault.",
                               subtitle: "Logins with passkeys and 2FA codes, cards, notes and addresses: end-to-end encrypted.").padding(.top, 48)
                    if let error { Text(error).foregroundColor(.red) }
                    if !model.signedIn {
                        Button { Task { do { try await model.startSignIn() } catch { self.error = error.localizedDescription } } } label: {
                            Text("Sign in with Jace").bold().frame(maxWidth: .infinity).padding(.vertical, 6)
                        }.buttonStyle(.borderedProminent)
                        Text("Sync your encrypted vault with your computer and browsers.").font(.footnote).foregroundColor(.secondary)
                        Button("Use on this phone only") { creating = true }.buttonStyle(.bordered)
                    } else if !checked {
                        ProgressView("Looking for your vault on Jace…")
                    } else {
                        Text("There's no vault on your Jace account yet.").foregroundColor(.secondary)
                        Button("Create your vault") { creating = true }.buttonStyle(.borderedProminent)
                        Button("Use a different Jace account") { model.signOut() }
                    }
                }.padding(24)
            }
            .task(id: model.signedIn) { if model.signedIn { remote = await model.remoteVault() }; checked = true }
        }
    }
}

struct CreateView: View {
    @EnvironmentObject var model: Model
    var onBack: () -> Void
    @State private var pw = ""
    @State private var pw2 = ""
    @State private var busy = false
    @State private var error: String?
    @State private var secretKey: String?
    var body: some View {
        if let secretKey {
            VStack(spacing: 16) {
                LogoHeader(title: "Save your Secret Key", subtitle: "You need it with your master password to open this vault on another device.")
                Text(secretKey).font(.system(.title3, design: .monospaced)).textSelection(.enabled).padding().background(Color(.secondarySystemBackground)).cornerRadius(12)
                Button("I saved it") { model.changed() }.buttonStyle(.borderedProminent)
            }.padding(24)
        } else {
            Form {
                Section { LogoHeader(title: "Create your vault").listRowBackground(Color.clear) }
                Section(footer: Text("A master password makes it end-to-end encrypted: only you can open it, and nobody can reset it for you.")) {
                    SecureField("Master password", text: $pw)
                    SecureField("Confirm master password", text: $pw2)
                }
                if let error { Text(error).foregroundColor(.red) }
                Button(busy ? "Encrypting…" : "Create vault") { make(pw == pw2 ? pw : nil, mismatch: pw != pw2) }.disabled(busy || pw.isEmpty)
                Section(footer: Text(model.signedIn ? "Still encrypted, but the Jace Passwords server holds its key for your account." :
                                        "Still encrypted, but anyone who can use this phone can open it.")) {
                    Button(model.signedIn ? "Skip: unlock with my Jace account" : "Skip: no master password") { make(nil, mismatch: false) }.disabled(busy)
                }
                Button("Back", action: onBack)
            }
        }
    }
    private func make(_ password: String?, mismatch: Bool) {
        if mismatch { error = "Those passwords don't match."; return }
        busy = true; error = nil
        Task {
            do { let sk = try await model.create(password: password); if let sk { secretKey = sk } }
            catch { self.error = error.localizedDescription }
            busy = false
        }
    }
}

// MARK: unlocking
struct UnlockView: View {
    @EnvironmentObject var model: Model
    let restore: Bool, keyMode: String, needsSecretKey: Bool
    @State private var password = ""
    @State private var secretKey = ""
    @State private var rememberHere = false
    @State private var busy = false
    @State private var error: String?
    var body: some View {
        Form {
            Section {
                LogoHeader(title: restore ? "Open your vault" : "Unlock Jace Passwords",
                           subtitle: keyMode == "jace" ? "This vault unlocks with your Jace account." : keyMode == "device" ? "This vault opens on this phone without a password." : nil)
                    .listRowBackground(Color.clear)
            }
            if keyMode == "password" {
                Section {
                    SecureField("Master password", text: $password)
                    if needsSecretKey { TextField("Secret Key (J1-…)", text: $secretKey).textInputAutocapitalization(.characters).autocorrectionDisabled() }
                    Toggle("Remember my password on this phone", isOn: $rememberHere)
                }
            }
            if let error { Text(error).foregroundColor(.red) }
            Button(busy ? "Unlocking…" : keyMode == "jace" ? "Unlock with Jace" : keyMode == "device" ? "Open" : "Unlock") {
                busy = true; error = nil
                Task {
                    do {
                        if restore { try await model.restore(password: password.isEmpty ? nil : password, secretKey: secretKey.isEmpty ? nil : secretKey) }
                        else { try await model.unlock(password: password.isEmpty ? nil : password, secretKey: secretKey.isEmpty ? nil : secretKey) }
                        if rememberHere && keyMode == "password" { try? model.vault.remember(true) }
                    } catch { self.error = error.localizedDescription }
                    busy = false
                }
            }.disabled(busy || (keyMode == "password" && password.isEmpty))
        }
    }
}

// MARK: the vault
func subtitle(_ i: [String: Any]) -> String {
    let f = i["fields"] as? [String: Any] ?? [:]
    switch i["type"] as? String {
    case "login": return (f["username"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? ((f["urls"] as? [String])?.first ?? "")
    case "card": return "\((f["brand"] as? String) ?? "Card") •••• \(String(((f["number"] as? String) ?? "").suffix(4)))"
    case "note": return String(((f["body"] as? String) ?? "").split(separator: "\n").first ?? "")
    case "identity": return (f["fullName"] as? String) ?? (f["email"] as? String) ?? ""
    case "alias": return (f["alias"] as? String) ?? ""
    default: return ""
    }
}

struct Tile: View {
    let title: String, type: String
    var body: some View {
        let icon = ["card": "💳", "note": "📝", "identity": "🪪", "alias": "📧"][type]
        let h = abs(title.unicodeScalars.reduce(0) { ($0 &* 31) &+ Int($1.value) }) % 360
        Text(icon ?? String(title.first.map { String($0).uppercased() } ?? "?")).font(.headline).foregroundColor(.white)
            .frame(width: 40, height: 40).background(icon != nil ? Color(red: 0.23, green: 0.27, blue: 0.77) : Color(hue: Double(h) / 360, saturation: 0.55, brightness: 0.75))
            .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

struct HomeView: View {
    @EnvironmentObject var model: Model
    @State private var query = ""
    @State private var filter = "all"
    @State private var adding = false
    private let filters = [("all", "All"), ("login", "Logins"), ("card", "Cards"), ("note", "Notes"), ("identity", "Identities"), ("2fa", "2FA codes")]
    var body: some View {
        let _ = model.tick
        let items = model.vault.items()
            .filter { i in filter == "all" ? true : filter == "2fa" ? !(((i["fields"] as? [String: Any])?["totp"] as? String) ?? "").isEmpty : i["type"] as? String == filter }
            .filter { i in query.isEmpty || "\(i["title"] ?? "") \(subtitle(i))".localizedCaseInsensitiveContains(query) }
            .sorted { ($0["title"] as? String ?? "").lowercased() < ($1["title"] as? String ?? "").lowercased() }
        NavigationStack {
            List {
                Section {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack { ForEach(filters, id: \.0) { f in
                            Button(f.1) { filter = f.0 }.buttonStyle(.bordered).tint(filter == f.0 ? jaceGreen : .secondary)
                        } }
                    }
                }.listRowBackground(Color.clear)
                ForEach(items.indices, id: \.self) { n in
                    let i = items[n]
                    NavigationLink(value: i["id"] as? String ?? "") {
                        HStack(spacing: 14) {
                            Tile(title: i["title"] as? String ?? "", type: i["type"] as? String ?? "")
                            VStack(alignment: .leading) {
                                Text(i["title"] as? String ?? "").bold().lineLimit(1)
                                Text(subtitle(i)).font(.footnote).foregroundColor(.secondary).lineLimit(1)
                            }
                        }
                    }
                }
                if items.isEmpty { Text(query.isEmpty ? "Nothing here yet. Tap + to add a login." : "No matches.").foregroundColor(.secondary) }
            }
            .searchable(text: $query, prompt: "Search your vault")
            .refreshable { await model.sync() }
            .navigationTitle("Jace Passwords")
            .navigationDestination(for: String.self) { ItemView(id: $0) }
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) { NavigationLink { SettingsView() } label: { Image(systemName: "gearshape") } }
                ToolbarItem(placement: .navigationBarTrailing) { Button { model.lock() } label: { Image(systemName: "lock") } }
                ToolbarItem(placement: .navigationBarTrailing) { Button { adding = true } label: { Image(systemName: "plus") } }
            }
            .sheet(isPresented: $adding) { NavigationStack { EditLoginView(id: nil) } }
        }
    }
}

struct FieldRow: View {
    @EnvironmentObject var model: Model
    let label: String, value: String
    var secret = false, mono = false
    @State private var shown = false
    var body: some View {
        if !value.isEmpty {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(label).font(.caption).foregroundColor(.secondary)
                    Text(secret && !shown ? String(repeating: "•", count: 12) : value).font(mono || secret ? .system(.body, design: .monospaced) : .body).textSelection(.enabled)
                }
                Spacer()
                if secret { Button { shown.toggle() } label: { Image(systemName: shown ? "eye.slash" : "eye") }.buttonStyle(.borderless) }
                Button { model.copy(value) } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless)
            }
        }
    }
}

struct TotpRow: View {
    @EnvironmentObject var model: Model
    let secret: String
    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { ctx in
            if let c = try? Totp.code(secret, at: ctx.date) {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("One-time password (2FA)").font(.caption).foregroundColor(.secondary)
                        Text(c.code.count == 6 ? "\(c.code.prefix(3)) \(c.code.suffix(3))" : c.code).font(.system(.title, design: .monospaced).bold()).foregroundColor(jaceGreen)
                    }
                    Spacer()
                    Text("\(c.remaining)s").foregroundColor(.secondary)
                    Button { model.copy(c.code) } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless)
                }
            }
        }
    }
}

struct ItemView: View {
    @EnvironmentObject var model: Model
    @Environment(\.dismiss) private var dismiss
    let id: String
    @State private var editing = false
    @State private var confirm = false
    var body: some View {
        let _ = model.tick
        if let item = model.vault.item(id) {
            let f = item["fields"] as? [String: Any] ?? [:]
            let s = { (k: String) in (f[k] as? String) ?? "" }
            List {
                Section {
                    switch item["type"] as? String {
                    case "login":
                        FieldRow(label: "Username", value: s("username"))
                        FieldRow(label: "Password", value: s("password"), secret: true)
                        if !s("totp").isEmpty { TotpRow(secret: s("totp")) }
                    case "card":
                        FieldRow(label: "Cardholder", value: s("cardholder"))
                        FieldRow(label: "Card number", value: s("number"), secret: true, mono: true)
                        FieldRow(label: "Expires", value: [s("expMonth"), s("expYear")].filter { !$0.isEmpty }.joined(separator: "/"))
                        FieldRow(label: "Security code", value: s("cvv"), secret: true)
                    case "identity":
                        ForEach([("fullName", "Name"), ("email", "Email"), ("phone", "Phone"), ("address1", "Address"), ("city", "City"), ("state", "State"), ("zip", "ZIP"), ("country", "Country")], id: \.0) {
                            FieldRow(label: $0.1, value: s($0.0))
                        }
                    case "note": FieldRow(label: "Note", value: s("body"))
                    default: FieldRow(label: "Alias", value: s("alias"))
                    }
                }
                let urls = ((f["urls"] as? [String]) ?? []).filter { !$0.isEmpty && !$0.hasPrefix("androidapp://") }
                if !urls.isEmpty { Section { ForEach(urls, id: \.self) { u in
                    HStack { FieldRow(label: "Website", value: u)
                        if let url = URL(string: u.contains("://") ? u : "https://\(u)") { Link(destination: url) { Image(systemName: "arrow.up.right.square") } }
                    }
                } } }
                if item["type"] as? String != "note", !s("notes").isEmpty { Section { FieldRow(label: "Notes", value: s("notes")) } }
                Section { Button("Move to Trash", role: .destructive) { confirm = true } }
            }
            .navigationTitle(item["title"] as? String ?? "")
            .toolbar { if item["type"] as? String == "login" { Button("Edit") { editing = true } } }
            .sheet(isPresented: $editing) { NavigationStack { EditLoginView(id: id) } }
            .confirmationDialog("Move to Trash?", isPresented: $confirm) {
                Button("Move to Trash", role: .destructive) { try? model.vault.trash(id); model.changed(); Task { await model.sync() }; dismiss() }
            }
        }
    }
}

struct EditLoginView: View {
    @EnvironmentObject var model: Model
    @Environment(\.dismiss) private var dismiss
    let id: String?
    @State private var title = ""
    @State private var username = ""
    @State private var password = ""
    @State private var website = ""
    @State private var totp = ""
    @State private var notes = ""
    @State private var loaded = false
    var body: some View {
        let totpError: String? = totp.isEmpty ? nil : ((try? Totp.parse(totp)) == nil ? "That 2FA setup key doesn't look right." : nil)
        Form {
            TextField("Title", text: $title)
            TextField("Username or email", text: $username).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.emailAddress)
            HStack { TextField("Password", text: $password).textInputAutocapitalization(.never).autocorrectionDisabled().font(.system(.body, design: .monospaced))
                Button("Generate") { password = Self.generate() } }
            TextField("Website (example.com)", text: $website).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
            Section(footer: Text(totpError ?? "A 2FA setup key, an otpauth:// link, or steam:// for Steam Guard.")) {
                TextField("2FA setup key", text: $totp).textInputAutocapitalization(.never).autocorrectionDisabled()
                Link("Steam Guard? How to add Steam's codes", destination: URL(string: "https://jace-passwords.vercel.app/steam")!)
            }
            Section("Notes") { TextEditor(text: $notes).frame(minHeight: 90) }
        }
        .navigationTitle(id == nil ? "New login" : "Edit login")
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) { Button("Save") { save() }.disabled(totpError != nil) }
        }
        .onAppear {
            guard !loaded, let id, let it = model.vault.item(id) else { return }
            loaded = true
            let f = it["fields"] as? [String: Any] ?? [:]
            title = it["title"] as? String ?? ""; username = f["username"] as? String ?? ""; password = f["password"] as? String ?? ""
            website = (f["urls"] as? [String])?.first ?? ""; totp = f["totp"] as? String ?? ""; notes = f["notes"] as? String ?? ""
        }
    }
    private func save() {
        let w = website.trimmingCharacters(in: .whitespaces)
        let fields: [String: Any] = ["username": username.trimmingCharacters(in: .whitespaces), "password": password,
                                     "urls": w.isEmpty ? [] : [w.contains("://") ? w : "https://\(w)"], "totp": totp.trimmingCharacters(in: .whitespaces), "notes": notes]
        let t = title.isEmpty ? (URL(string: w.contains("://") ? w : "https://\(w)")?.host ?? "Login") : title
        if let id { try? model.vault.updateItem(id, title: t, fields: fields) } else { try? model.vault.addItem(type: "login", title: t, fields: fields) }
        model.changed(); Task { await model.sync() }
        dismiss()
    }
    static func generate(_ length: Int = 20) -> String {
        let sets = ["abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#$%^&*-_=+?"].map(Array.init)
        let all = sets.flatMap { $0 }
        var chars = sets.map { $0[Int(JPCrypto.rand(1)[0]) % $0.count] }
        while chars.count < length { chars.append(all[Int(JPCrypto.rand(1)[0]) % all.count]) }
        return String(chars.shuffled())
    }
}

// MARK: settings
struct SettingsView: View {
    @EnvironmentObject var model: Model
    @State private var remembered = false
    var body: some View {
        let _ = model.tick
        Form {
            Section(header: Text("Autofill in Safari"), footer: Text("Websites in Safari, including sign-ins that apps open in Safari. For sign-ins inside other apps, copy from Jace Passwords.")) {
                Text("Turn on the Jace Passwords extension: Settings → Apps → Safari → Extensions → Jace Passwords → allow it, and \"All Websites\". Then tap the Jace Passwords icon in Safari's address bar to sign in with Jace.")
                    .font(.footnote)
            }
            Section("Jace account") {
                if let a = model.account {
                    Text("@\(a["username"] as? String ?? "") · \(model.syncStatus.isEmpty ? "Synced with Jace" : model.syncStatus)").foregroundColor(.secondary)
                    Button("Sync now") { Task { await model.sync() } }
                    Button("Sign out", role: .destructive) { model.signOut() }
                } else {
                    Button("Sign in with Jace") { Task { try? await model.startSignIn() } }
                }
            }
            if model.vault.keyMode == "password" {
                Section(footer: Text("Opens without typing it. Anyone who can use this phone can open your vault.")) {
                    Toggle("Remember my master password on this phone", isOn: $remembered)
                        .onChange(of: remembered) { on in try? model.vault.remember(on) }
                }
            }
            Section(header: Text("Updates"), footer: Text("Add this source once in AltStore or SideStore (Sources → +); they update Jace Passwords from it.")) {
                Text("Version \(model.version)").foregroundColor(.secondary)
                if let u = model.update {
                    Text("Version \(u.version) is available.")
                    if let url = URL(string: "altstore://") { Link("Update in AltStore", destination: url) }
                    if let url = URL(string: "sidestore://") { Link("Update in SideStore", destination: url) }
                } else {
                    Button("Check for updates") { Task { await model.checkUpdates() } }
                }
                Button("Copy the AltStore / SideStore source") { UIPasteboard.general.string = Model.source }
            }
            Section { Button("Lock now") { model.lock() } }
        }
        .navigationTitle("Settings")
        .onAppear { remembered = model.vault.remembered }
    }
}
