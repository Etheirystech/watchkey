# watchkey

Access macOS Keychain secrets with Touch ID & Apple Watch — like [pam-watchid](https://github.com/mostpinkest/pam-watchid), but for keychain items.

Instead of typing your password every time a script reads a secret from the keychain, authenticate with a tap on your Apple Watch or a finger on Touch ID.

## Install

```bash
# Build and install to /usr/local/bin
make install

# Or with a custom prefix
make install PREFIX=~/.local
```

Requires Xcode Command Line Tools (`xcode-select --install`).

## Usage

```bash
# Import an existing keychain secret (one-time)
watchkey set DOPPLER_TOKEN_DEV --import

# Retrieve with Touch ID / Apple Watch
watchkey get DOPPLER_TOKEN_DEV

# Store a new secret (reads from stdin)
watchkey set MY_SECRET

# Pipe a value in
echo "s3cret" | watchkey set MY_SECRET

# Delete a stored secret
watchkey delete MY_SECRET
```

All `get`, `set`, and `delete` operations require authentication.

If Touch ID and Apple Watch are unavailable, watchkey falls back to a system password prompt.

## Example: Doppler + Next.js

Before:
```json
{
  "dev": "DOPPLER_TOKEN=\"$(security find-generic-password -w -s 'DOPPLER_TOKEN_DEV')\" doppler run -- next dev --turbopack"
}
```

After:
```json
{
  "dev": "DOPPLER_TOKEN=\"$(watchkey get DOPPLER_TOKEN_DEV)\" doppler run -- next dev --turbopack"
}
```

## How it works

1. Secrets are stored in the login keychain as generic passwords, namespaced under the `watchkey` account
2. On retrieval, watchkey authenticates via `LAContext` using `deviceOwnerAuthenticationWithBiometricsOrCompanion` (macOS 15+) or `deviceOwnerAuthenticationWithBiometricsOrWatch` (older versions) — the same API that [pam-watchid](https://github.com/mostpinkest/pam-watchid) uses for sudo
3. If biometrics/watch aren't available, it falls back to `deviceOwnerAuthentication` (system password dialog)

## Requirements

- macOS 13+
- Apple Watch paired for unlock, or Touch ID

## Uninstall

```bash
make uninstall
```
