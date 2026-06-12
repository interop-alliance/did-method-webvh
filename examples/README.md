# DID Web VH Resolver Examples

This directory contains example implementations for the `didwebvh-ts` library:

1. **Express Resolver** - A DID resolver built with Express (Node.js)
2. **Signer** - A custom signer implementation extending `AbstractCrypto`

The resolver example demonstrates functioning DID resolution with proper Ed25519 cryptographic verification.

## Prerequisites

- Node.js >= 20.19

## Setup

The examples consume `didwebvh-ts` from the repository's build output (via the `file:..` dependency), so build the library first:

```bash
# From the repository root
npm install
npm run build

# Then install the example dependencies
cd examples
npm install
```

## Running the Examples

### Express Resolver

The Express resolver demonstrates a resolver with an HSM Ed25519 implementation:

```bash
# From the repository root
npm run dev

# Or directly
npx tsx examples/express-resolver.ts
```

This will start the resolver on port 8000.

### Signer

```bash
npm run example:signer
```

## Testing the Resolver

You can test the resolver by making HTTP requests to the resolution endpoints (see also [resolve.http](resolve.http)):

### Resolving a DID

```bash
curl "http://localhost:8000/resolve/did:web:example.com"
```

### Resolving with Query Parameters

You can pass various query parameters for version control:

```bash
# Version number
curl "http://localhost:8000/resolve/did:web:example.com?versionNumber=1"

# Version ID
curl "http://localhost:8000/resolve/did:web:example.com?versionId=abc123"

# Version time
curl "http://localhost:8000/resolve/did:web:example.com?versionTime=2023-12-01T00:00:00Z"

# Verification method
curl "http://localhost:8000/resolve/did:web:example.com?verificationMethod=key-1"
```

## Implementation Details

### Express Resolver

The Express resolver uses an Ed25519 verifier class that:

1. Implements the `Verifier` interface directly
2. Simulates an HSM (Hardware Security Module) for secure Ed25519 key operations
3. Uses Ed25519 for cryptographic operations via `@stablelib/ed25519`

### Code Structure

1. **Ed25519 Verifier Implementation**: Proper cryptographic verification using the Ed25519 algorithm
2. **DID Resolution**: Endpoints for resolving DIDs using the `didwebvh-ts` library
3. **File Handling**: Logic for retrieving resources associated with DIDs
4. **Error Handling**: Proper error reporting for various scenarios

## Security Considerations

These examples demonstrate proper Ed25519 cryptographic verification but should be reviewed for your specific security requirements before use in production:

1. Key management should be handled securely (HSM, key vaults, etc.)
2. Input validation should be robust
3. Error handling should not leak sensitive information
4. Rate limiting may be needed in production deployments

## License

See the project's main license file for details.
