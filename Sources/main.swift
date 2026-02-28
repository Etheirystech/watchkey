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

    let policy: LAPolicy
    if context.canEvaluatePolicy(bioPolicy, error: &error) {
        policy = bioPolicy
    } else {
        // Fall back to password-based auth
        var passError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &passError) else {
            fputs("Error: No authentication method available", stderr)
            if let passError {
                fputs(" (\(passError.localizedDescription))", stderr)
            }
            fputs("\n", stderr)
            exit(1)
        }
        policy = .deviceOwnerAuthentication
    }

    let sem = DispatchSemaphore(value: 0)
    var authError: Error?

    context.evaluatePolicy(policy, localizedReason: reason) { success, error in
        if !success { authError = error }
        sem.signal()
    }
    sem.wait()

    if let authError {
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
      watchkey set <service> --import     Import from existing keychain item
      watchkey delete <service>           Delete a stored secret

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
    guard args.count >= 2 else {
        fputs("Error: Missing service name\n", stderr)
        printUsage()
        exit(1)
    }
    print(getItem(service: args[1]), terminator: "")

case "set":
    guard args.count >= 2 else {
        fputs("Error: Missing service name\n", stderr)
        printUsage()
        exit(1)
    }
    let service = args[1]
    authenticate(reason: "store \"\(service)\" in keychain")
    let value: String
    if args.contains("--import") {
        fputs("Importing \"\(service)\" from keychain...\n", stderr)
        value = importFromKeychain(service: service)
    } else {
        value = readValue()
    }
    storeItem(service: service, value: value)

case "delete":
    guard args.count >= 2 else {
        fputs("Error: Missing service name\n", stderr)
        printUsage()
        exit(1)
    }
    deleteItem(service: args[1])

case "help", "--help", "-h":
    printUsage()

default:
    fputs("Unknown command: \(command)\n", stderr)
    printUsage()
    exit(1)
}
