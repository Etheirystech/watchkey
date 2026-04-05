import AppKit
import Foundation
import LocalAuthentication
import Security

// MARK: - Constants

/// Account name used to namespace watchkey items in the keychain
let keychainAccount = "watchkey"

// MARK: - Terminal State

/// Saved terminal state for signal handler restoration
var savedTermios = termios()
var termiosNeedRestore = false

func restoreTerminal() {
    if termiosNeedRestore {
        tcsetattr(fileno(stdin), TCSANOW, &savedTermios)
        termiosNeedRestore = false
        fputs("\n", stderr)
    }
}

func installSignalHandlers() {
    let handler: @convention(c) (Int32) -> Void = { _ in
        restoreTerminal()
        exit(1)
    }
    signal(SIGINT, handler)
    signal(SIGTERM, handler)
}

// MARK: - Biometric Authentication

/// Evaluates a policy synchronously. Returns nil on success, or the error on failure.
func evaluatePolicy(_ policy: LAPolicy, context: LAContext, reason: String) -> Error? {
    let sem = DispatchSemaphore(value: 0)
    var authError: Error?

    context.evaluatePolicy(policy, localizedReason: reason) { success, error in
        if !success { authError = error }
        sem.signal()
    }
    sem.wait()

    return authError
}

/// Authenticates via Touch ID, Apple Watch, or system password.
/// Tries biometric+watch first, falls back to device owner auth (password).
func authenticate(reason: String) {
    let context = LAContext()
    var error: NSError?

    // Try biometric + Apple Watch first
    let bioPolicy: LAPolicy
    if #available(macOS 15, *) {
        bioPolicy = .deviceOwnerAuthenticationWithBiometricsOrCompanion
    } else {
        bioPolicy = .deviceOwnerAuthenticationWithBiometricsOrWatch
    }

    if context.canEvaluatePolicy(bioPolicy, error: &error) {
        let bioError = evaluatePolicy(bioPolicy, context: context, reason: reason)
        if bioError == nil { return }

        // User clicked "Use Password" or biometric failed — retry with password
        let userCancelled = (bioError as? LAError)?.code == .userCancel
        if userCancelled {
            fputs("Authentication cancelled.\n", stderr)
            exit(1)
        }
    }

    // Fall back to password-based auth
    let passContext = LAContext()
    var passError: NSError?
    guard passContext.canEvaluatePolicy(.deviceOwnerAuthentication, error: &passError) else {
        fputs("Error: No authentication method available", stderr)
        if let passError {
            fputs(" (\(passError.localizedDescription))", stderr)
        }
        fputs("\n", stderr)
        exit(1)
    }

    if let authError = evaluatePolicy(.deviceOwnerAuthentication, context: passContext, reason: reason) {
        fputs("Authentication failed: \(authError.localizedDescription)\n", stderr)
        exit(1)
    }
}

// MARK: - Keychain Operations

func storeItem(service: String, value: String) {
    // Delete any existing item with this service+account pair
    let deleteQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: keychainAccount,
        kSecUseDataProtectionKeychain as String: false,
    ]
    SecItemDelete(deleteQuery as CFDictionary)

    guard let data = value.data(using: .utf8) else {
        fputs("Error: Value contains invalid characters\n", stderr)
        exit(1)
    }

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: keychainAccount,
        kSecValueData as String: data,
        kSecUseDataProtectionKeychain as String: false,
    ]

    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
        let msg = SecCopyErrorMessageString(status, nil) as String? ?? "code \(status)"
        fputs("Error: Failed to store item: \(msg)\n", stderr)
        exit(1)
    }

    fputs("Stored \"\(service)\" (auth required for access).\n", stderr)
}

func getItem(service: String) -> String {
    authenticate(reason: "access \"\(service)\" from keychain")

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: keychainAccount,
        kSecReturnData as String: true,
        kSecUseDataProtectionKeychain as String: false,
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    guard status == errSecSuccess,
          let data = result as? Data,
          let value = String(data: data, encoding: .utf8)
    else {
        if status == errSecItemNotFound {
            fputs("Error: No item found for \"\(service)\"\n", stderr)
            fputs("Store one first: watchkey set \(service)\n", stderr)
        } else {
            let msg = SecCopyErrorMessageString(status, nil) as String? ?? "code \(status)"
            fputs("Error: \(msg)\n", stderr)
        }
        exit(1)
    }

    return value
}

func deleteItem(service: String) {
    authenticate(reason: "delete \"\(service)\" from keychain")

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: keychainAccount,
        kSecUseDataProtectionKeychain as String: false,
    ]

    let status = SecItemDelete(query as CFDictionary)
    switch status {
    case errSecSuccess:
        fputs("Deleted \"\(service)\".\n", stderr)
    case errSecItemNotFound:
        fputs("Error: No item found for \"\(service)\"\n", stderr)
        exit(1)
    default:
        let msg = SecCopyErrorMessageString(status, nil) as String? ?? "code \(status)"
        fputs("Error: \(msg)\n", stderr)
        exit(1)
    }
}

func listItems() -> [String] {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: keychainAccount,
        kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitAll,
        kSecUseDataProtectionKeychain as String: false,
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    guard status == errSecSuccess, let items = result as? [[String: Any]] else {
        if status == errSecItemNotFound { return [] }
        let msg = SecCopyErrorMessageString(status, nil) as String? ?? "code \(status)"
        fputs("Error: \(msg)\n", stderr)
        exit(1)
    }

    return items.compactMap { $0[kSecAttrService as String] as? String }.sorted()
}

// MARK: - Input Helpers

/// Read a value from stdin — suppresses echo in interactive mode.
func readValue() -> String {
    if isatty(fileno(stdin)) != 0 {
        fputs("Enter value: ", stderr)

        tcgetattr(fileno(stdin), &savedTermios)
        var newTerm = savedTermios
        newTerm.c_lflag &= ~tcflag_t(ECHO)
        tcsetattr(fileno(stdin), TCSANOW, &newTerm)
        termiosNeedRestore = true

        let line = readLine(strippingNewline: true)

        restoreTerminal()

        guard let value = line, !value.isEmpty else {
            fputs("Error: No value provided\n", stderr)
            exit(1)
        }
        return value
    } else {
        let data = FileHandle.standardInput.readDataToEndOfFile()
        guard let value = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .newlines),
              !value.isEmpty
        else {
            fputs("Error: No value provided on stdin\n", stderr)
            exit(1)
        }
        return value
    }
}

/// Read a value via a native macOS secure input dialog.
func readValueGUI(service: String) -> String {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    if #available(macOS 14, *) {
        app.activate()
    } else {
        app.activate(ignoringOtherApps: true)
    }

    let alert = NSAlert()
    alert.messageText = "Store secret"
    alert.informativeText = "Enter value for \"\(service)\":"
    alert.alertStyle = .informational
    alert.addButton(withTitle: "Store")
    alert.addButton(withTitle: "Cancel")
    if let keychainIcon = NSImage(contentsOfFile: "/System/Library/CoreServices/Applications/Keychain Access.app/Contents/Resources/AppIcon.icns") {
        keychainIcon.size = NSSize(width: 48, height: 48)
        alert.icon = keychainIcon
    }

    let input = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 24))
    input.placeholderString = "Secret value"
    alert.accessoryView = input
    alert.window.initialFirstResponder = input

    let response = alert.runModal()
    guard response == .alertFirstButtonReturn else {
        fputs("Cancelled.\n", stderr)
        exit(1)
    }

    let value = input.stringValue
    guard !value.isEmpty else {
        fputs("Error: No value provided\n", stderr)
        exit(1)
    }

    return value
}

/// Import a value from the existing macOS keychain using `security` CLI.
func importFromKeychain(service: String) -> String {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/usr/bin/security")
    proc.arguments = ["find-generic-password", "-w", "-s", service]

    let pipe = Pipe()
    proc.standardOutput = pipe
    proc.standardError = FileHandle.nullDevice

    do {
        try proc.run()
    } catch {
        fputs("Error: Failed to run security command: \(error.localizedDescription)\n", stderr)
        exit(1)
    }

    // Read pipe before waiting to avoid deadlock if output exceeds buffer
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    proc.waitUntilExit()

    guard proc.terminationStatus == 0 else {
        fputs("Error: Could not read \"\(service)\" from keychain (exit \(proc.terminationStatus))\n", stderr)
        fputs("Make sure the item exists: security find-generic-password -s '\(service)'\n", stderr)
        exit(1)
    }

    guard let value = String(data: data, encoding: .utf8)?
        .trimmingCharacters(in: .newlines),
          !value.isEmpty
    else {
        fputs("Error: Empty value for \"\(service)\" in keychain\n", stderr)
        exit(1)
    }

    return value
}

// MARK: - CLI

func printUsage() {
    fputs("""
    watchkey — Access keychain secrets with Touch ID & Apple Watch

    Usage:
      watchkey get <service>              Retrieve a secret
      watchkey set <service>              Store a secret (reads from stdin)
      watchkey set <service> --gui        Store a secret via secure dialog
      watchkey set <service> --import     Import from existing keychain item
      watchkey delete <service>           Delete a stored secret
      watchkey list                       List all stored keys

    Examples:
      watchkey set DOPPLER_TOKEN_DEV --import
      DOPPLER_TOKEN="$(watchkey get DOPPLER_TOKEN_DEV)" doppler run -- next dev

    """, stderr)
}

installSignalHandlers()

let args = Array(CommandLine.arguments.dropFirst())

guard let command = args.first else {
    printUsage()
    exit(1)
}

switch command {
case "get":
    let getService: String
    if args.count >= 2 {
        getService = args[1]
    } else {
        fputs("Key name: ", stderr)
        guard let line = readLine(strippingNewline: true), !line.isEmpty else {
            fputs("Error: No key name provided\n", stderr)
            exit(1)
        }
        getService = line
    }
    print(getItem(service: getService), terminator: "")

case "set":
    let setFlags = args.dropFirst().filter { $0.hasPrefix("--") }
    let setArgs = args.dropFirst().filter { !$0.hasPrefix("--") }
    let service: String
    if let name = setArgs.first {
        service = name
    } else {
        fputs("Key name: ", stderr)
        guard let line = readLine(strippingNewline: true), !line.isEmpty else {
            fputs("Error: No key name provided\n", stderr)
            exit(1)
        }
        service = line
    }
    authenticate(reason: "store \"\(service)\" in keychain")
    let value: String
    if setFlags.contains("--import") {
        fputs("Importing \"\(service)\" from keychain...\n", stderr)
        value = importFromKeychain(service: service)
    } else if setFlags.contains("--gui") {
        value = readValueGUI(service: service)
    } else {
        value = readValue()
    }
    storeItem(service: service, value: value)

case "list":
    for service in listItems() {
        print(service)
    }

case "delete":
    let delService: String
    if args.count >= 2 {
        delService = args[1]
    } else {
        fputs("Key name: ", stderr)
        guard let line = readLine(strippingNewline: true), !line.isEmpty else {
            fputs("Error: No key name provided\n", stderr)
            exit(1)
        }
        delService = line
    }
    deleteItem(service: delService)

case "help", "--help", "-h":
    printUsage()

default:
    fputs("Unknown command: \(command)\n", stderr)
    printUsage()
    exit(1)
}
