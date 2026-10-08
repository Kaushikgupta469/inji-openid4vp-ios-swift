# Integration Guide

This guide provides detailed information on integrating the OpenID4VP SDK into your wallet application.

## Table of Contents

- [Functionalities](#functionalities)
- [Verifiable Presentation Construction](#verifiable-presentation-construction)
  - [1. ldp_vp Construction](#1-ldp_vp-construction)
  - [2. SD-JWT VP Construction](#2-sd-jwt-vp-construction)
  - [3. MDOC VP Construction](#3-mdoc-vp-construction)
- [Configuring Your Wallet (WalletConfig)](#configuring-your-wallet-walletconfig)
  - [What is WalletConfig?](#what-is-walletconfig)
  - [Quick Example](#quick-example)
  - [WalletConfig Parameters](#walletconfig-parameters)
  - [Configuring Trusted Verifiers](#configuring-trusted-verifiers)
  - [About Wallet Metadata](#about-wallet-metadata)
- [Initializing OpenID4VP](#initializing-openid4vp)
  - [Basic Instantiation](#basic-instantiation)
  - [Initialization Parameters](#initialization-parameters)
  - [Common Initialization Patterns](#common-initialization-patterns)
  - [When to Provide jsonLdCanonicalizer](#when-to-provide-jsonldcanonicalizer)
- [Integration Workflows](#integration-workflows)
  - [1. Resolve and Validate Authorization Request URI](#1-resolve-and-validate-authorization-request-uri)
  - [2. User Selection of Credentials and Consent](#2-user-selection-of-credentials-and-consent)
  - [3. Construction of a Verifiable Presentation and Submission to the Verifier](#3-construction-of-a-verifiable-presentation-and-submission-to-the-verifier)
  - [4. Dispatch Error to Verifier](#4-dispatch-errors-to-the-verifier)

---

## Functionalities

- Decode and process the Verifier's encoded Authorization Request.
    - Authenticate the Verifier based on the identified Client ID prefix.
    - Validate the Authorization Request structure in accordance with the OpenID4VP specification.
    - Provide the validated Authorization Request (Presentation Definition or DCQL query) to the Wallet.
- Prepare the Verifiable Presentation response by requesting the Wallet to sign the required data.
- Submit the Authorization Response to the Verifier in accordance with the received presentation request.


> **Note:** Fetching Verifiable Presentations request via the [`scope`](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-using-scope-parameter-to-re) parameter is not supported by this SDK.

## Verifiable Presentation Construction

The library SDK supports the construction of Verifiable Presentations (VPs) for the following credential formats:

* `ldp_vp`
* `dc+sd-jwt` / `vc+sd-jwt`
* `mso_mdoc`

The VP construction process applies the required cryptographic holder binding based on the credential format and the presentation request type.

---

## 1. `ldp_vp` Construction

For each shared credential with the format `ldp_vc`, the SDK constructs an `ldp_vp` presentation.

The holder key is identified from the credential subject ID. This holder key is used for cryptographic holder binding in the VP proof.

### Presentation Exchange Request

For Presentation Exchange requests:

* The credential subject ID is used to identify the holder key.
* The identified holder key is used to generate the VP proof for cryptographic holder binding.

### DCQL Request

For DCQL-based requests, the `require_cryptographic_holder_binding` proof parameter determines whether holder binding is required:

* If cryptographic holder binding is required:

    * The VP is generated with a proof.
    * The proof's verification method references the holder key.
* If cryptographic holder binding is not required:

    * The credential can be shared directly as a Verifiable Credential.

### Supported VP Construction

**Holder Key Identification**

* The holder key is identified using `credentialSubject.id`.
* For `ldp_vc`, VP construction supports only single-subject credentials. Credentials with multiple `credentialSubject` entries are currently not supported.


**Supported VP proof signature suite:**

* `JsonWebSignatureSuite2020` — for W3C VC Data Model `1.1` credentials
* `DataIntegrityProof` — for W3C VC Data Model `2.0` credentials, using cryptosuite `eddsa-rdfc-2022` (Ed25519 holder keys) or `ecdsa-rdfc-2019` (P-256 holder keys)

**Supported Holder key identification algorithms:**

| Data Model | Supported holder key algorithms        |
|------------|----------------------------------------|
| `1.1`      | `RS256`, `ES256`, `Ed25519`, `ES256K`  |
| `2.0`      | `Ed25519`, `ES256` only                |

**Supported W3C Verifiable Credential Data Model:**

* Version `1.1`
* Version `2.0` — the `https://www.w3.org/ns/credentials/v2` context must be the **first** entry of the credential's `@context` array.

> **Note:** A VC 2.0 credential whose holder key is neither Ed25519 nor P-256 cannot be presented by this SDK. Such credentials are **excluded from DCQL matching results** so that they are never offered to the user for selection. For Presentation Exchange requests, where the SDK performs no matching, constructing a presentation for such a credential fails instead.

> **Note:** VC 2.0 presentations reuse the existing `jsonLdCanonicalizer` callback. It must return `sha256(canonical proof configuration) || sha256(canonical document)`, where the proof configuration carries the document's `@context` and no `proofValue`. Unlike `JsonWebSignature2020`, the returned bytes are signed directly with no detached JWS header.
>
> The canonicalizer must also honour the type-scoped `"@container": "@graph"` on `verifiableCredential`; otherwise it canonicalizes a different dataset from the one verifiers use and every VC 2.0 presentation fails verification. Inji Wallet's canonicalizer does this from [inji-wallet#2590](https://github.com/inji/inji-wallet/pull/2590) onward.

---

## 2. SD-JWT VP Construction

The SDK constructs an SD-JWT Verifiable Presentation according to the IETF SD-JWT specification as profiled by OpenID4VP.

The holder key is identified using the `cnf` claim present in the credential. The identified key is used for generating the Key Binding JWT (KB-JWT) when cryptographic holder binding is required.

### Presentation Exchange Request

For Presentation Exchange requests:

* If the credential contains a `cnf` claim:

    * An SD-JWT VP with holder binding (KB-JWT) is generated.
* If the credential does not contain a `cnf` claim:

    * The SD-JWT VP is generated without holder binding.

### DCQL Request

For DCQL-based requests, the `require_cryptographic_holder_binding` proof parameter determines whether holder binding is required:

* If cryptographic holder binding is required:

    * An SD-JWT VP with KB-JWT is generated.
* If cryptographic holder binding is not required:

    * The SD-JWT VP is generated without a KB-JWT.

### **Supported holder key identification mechanisms:**

* JWK-based identification:

    * `ES256`
    * `ES384`
    * `ES256K`
    * `RS256`
    * `EdDSA`
* Key ID (`kid`) based identification:

    * Supports DID methods: `did:jwk`, `did:key`, `did:web`
    * Algorithms vary by DID method:
        * `did:jwk`: ES256, ES384, ES256K, RS256, EdDSA
        * `did:key`: EdDSA, ES256, ES384, ES256K
        * `did:web`: EdDSA, ES256

> **Note:** `vc+sd-jwt` credentials and presentations are currently supported for backward compatibility. Support for this format will be deprecated in a future release.

---

## 3. MDOC VP Construction

The SDK constructs an mdoc Verifiable Presentation according to ISO/IEC 18013-5 as referenced by OpenID4VP.

The holder key is identified using the `deviceKey` available in the `mso_mdoc` credential. This key is used for cryptographic holder binding in the presentation.

**Supported holder key identification algorithms:**

* `ES256`
* `EdDSA`

---

## Configuring Your Wallet (`WalletConfig`)

### What is WalletConfig?

`WalletConfig` tells the OpenID4VP library which features your wallet supports, which verifiers you trust, and how to validate incoming requests. It defines capabilities, cryptographic algorithms, and trusted verifier settings.

### Quick Example

**Scenario:** Configuring a wallet with trusted verifiers and credential format support

```swift
let trustedVerifiers = [
    Verifier(
        clientId: "trusted-bank",
        responseUris: ["https://bank.example/vp-response"],
        jwksUri: "https://bank.example/keys.json",
        allowUnsignedRequest: false
    )
]

let walletConfig = WalletConfig(
    vpFormatsSupported: [.ldp_vc, .mso_mdoc, .dc_sd_jwt],
    clientIdPrefixesSupported: [.preRegistered, .redirectUri, .decentralizedIdentifier],
    requestObjectSigningAlgValuesSupported: [.edDsa],
    authorizationEncryptionAlgValuesSupported: [.ecdhES],
    authorizationEncryptionEncValuesSupported: [.a256GCM],
    responseTypesSupported: [.vp_token],
    isPresentationDefinitionUriSupported: true,
    trustedVerifiers: trustedVerifiers,
    validateTrustedVerifier: true
)

let openID4VP = OpenID4VP(
    traceabilityId: UUID().uuidString,
    walletConfig: walletConfig,
    jsonLdCanonicalizer: myJsonLdCanonicalizerFunction  // Optional, required for ldp_vc support
)
```

### WalletConfig Parameters

**Table: WalletConfig Parameter Reference** - Configuration options for declaring wallet capabilities

| Parameter                                   | Type                     | Default                                                    | Purpose                                                       |
|---------------------------------------------|--------------------------|------------------------------------------------------------|---------------------------------------------------------------|
| `vpFormatsSupported`                        | `[VPFormatType]`         | `[ldp_vc, mso_mdoc, dc_sd_jwt]`                            | Verifiable Presentation formats your wallet supports          |
| `clientIdPrefixesSupported`                 | `[ClientIdPrefix]`       | `[.preRegistered, .redirectUri, .decentralizedIdentifier]` | Client ID prefix types your wallet can authenticate           |
| `requestObjectSigningAlgValuesSupported`    | `[SignatureAlgorithm]?`  | `[.edDsa]`                                                 | Signature algorithms accepted when validating signed requests |
| `authorizationEncryptionAlgValuesSupported` | `[EncryptionAlgorithm]?` | `[.ecdhES]`                                                | Supported key management algorithms for encryption            |
| `authorizationEncryptionEncValuesSupported` | `[EncryptionMethod]?`    | `[.a256GCM]`                                               | Supported content encryption methods                          |
| `responseTypesSupported`                    | `[ResponseType]`         | `[.vp_token]`                                              | OpenID4VP response types your wallet can generate             |
| `isPresentationDefinitionUriSupported`      | `Bool`                   | `true`                                                     | Whether wallet can resolve presentation definitions from URIs |
| `trustedVerifiers`                          | `[Verifier]`             | `[]`                                                       | Pre-configured trusted verifiers                              |
| `validateTrustedVerifier`                   | `Bool`                   | `true`                                                     | Whether to validate pre-registered verifiers                  |

### Configuring Trusted Verifiers

For pre-registered clients, configure each verifier you trust:

| Parameter              | Required | Purpose                                                    | Example                                |
|------------------------|:--------:|------------------------------------------------------------|----------------------------------------|
| `clientId`             |   Yes    | Unique identifier of the Verifier                          | `"trusted-bank"`                       |
| `responseUris`         |   Yes    | Permitted response endpoint(s) for Authorization Responses | `["https://bank.example/vp-response"]` |
| `jwksUri`              |    No    | URI with public keys for signature verification            | `"https://bank.example/keys.json"`     |
| `allowUnsignedRequest` |    No    | Whether to accept unsigned Authorization Requests          | `false` (default: require signatures)  |

**Example Verifier Configuration:**
```swift
Verifier(
    clientId: "my-trusted-verifier",
    responseUris: ["https://verifier.example/receive-vp"],
    jwksUri: "https://verifier.example/jwks.json",
    allowUnsignedRequest: false
)
```

### About Wallet Metadata

When a Verifier uses the `request_uri` flow with `POST`, the SDK automatically generates `WalletMetadata` from your `WalletConfig` and sends it to the Verifier. This tells the verifier which capabilities your wallet supports, allowing them to generate compatible Authorization Requests.

**Properties automatically communicated:**
- Supported VP formats → `vpFormatsSupported`
- Supported Client ID prefixes → `clientIdPrefixesSupported`
- Supported signing algorithms → `requestObjectSigningAlgValuesSupported`
- Supported encryption algorithms → `authorizationEncryptionAlgValuesSupported`
- Supported encryption methods → `authorizationEncryptionEncValuesSupported`
- Supported response types → `responseTypesSupported`
- URI support → `isPresentationDefinitionUriSupported`

You **do not** configure metadata manually—the SDK handles serialization automatically (different format for Draft 23 vs. OpenID4VP 1.0).

---

## Initializing OpenID4VP

After configuring your wallet, instantiate the `OpenID4VP` class. This creates a SDK instance that handles request validation, VP construction, and verifier communication.

> **⚠️ Important: One Flow Per Instance**
>
> Each SDK instance supports **only one OpenID4VP flow at a time**. If your application needs to handle multiple concurrent VP requests, create a separate `OpenID4VP` instance for each flow. Do not reuse an instance until the current flow completes (either successfully or with an error).


### Basic Instantiation

```swift
let openID4VP = OpenID4VP(
    traceabilityId: appId,
    walletConfig: walletConfig
)
```

### Initialization Parameters

| Parameter             | Type                           | Required | Purpose                                                                                                                                   |
|-----------------------|--------------------------------|:--------:|-------------------------------------------------------------------------------------------------------------------------------------------|
| `traceabilityId`      | `String`                       |  ✅ Yes   | Unique identifier for tracing and debugging (e.g., UUID, user session ID). Included in all error logs and responses.                      |
| `walletConfig`        | `WalletConfig`                 |   ❌ No   | Your wallet's configuration (defaults to empty `WalletConfig()` if omitted). Defines capabilities, trusted verifiers, and format support. |
| `jsonLdCanonicalizer` | `JsonLdCanonicalizerCallback?` |   ❌ No   | **Required only if supporting `ldp_vc` format** to canonicalize JSON-LD data for proof generation. Otherwise Optional.                    |

### Common Initialization Patterns

**Pattern 1: Minimal Setup (no ldp_vc support)**

Use this if your wallet only handles mso_mdoc or sd-jwt formats:

```swift
let openID4VP = OpenID4VP(
    traceabilityId: UUID().uuidString,
    walletConfig: walletConfig
)
```

**Pattern 2: With ldp_vc Support**

Use this if your wallet needs to support `ldp_vc` Verifiable Presentations:

```swift
let openID4VP = OpenID4VP(
    traceabilityId: UUID().uuidString,
    walletConfig: walletConfig,
    jsonLdCanonicalizer: myJsonLdCanonicalizerFunction  // Your custom canonicalizer
)
```

### When to Provide `jsonLdCanonicalizer`

The `jsonLdCanonicalizer` callback is **only needed** if:

✅ Your wallet config includes `.ldp_vc` in `vpFormatsSupported`  
✅ You expect to receive DCQL or Presentation Exchange requests containing `ldp_vc` credentials

If you omit it but receive an `ldp_vc` request, the SDK will throw an exception.

---

## Integration Workflows

This section describes the step-by-step workflow for integrating the OpenID4VP SDK into your wallet application.

## 1. Resolve and Validate Authorization Request URI

The Verifier prepares an OpenID4VP Authorization Request and shares it with the Wallet, either through a deep link or a QR code. Once the Wallet receives the Authorization Request, invoke the `authenticateVerifier` API from the Wallet to resolve the request, authenticate the Verifier, and perform validation of the Authorization Request in accordance with the OpenID4VP specification.

Upon successful validation, the API returns a fully resolved Authorization Request containing the presentation requirements (Presentation Definition or DCQL query), which can then be used by the Wallet to prepare the Verifiable Presentation response. 

### `authenticateVerifier` 

This method:
- Receives and validates the Verifier's encoded Authorization Request
- Validates the VP request and client verification
- Extracts the clientId and verifies it against the wallet's trusted verifiers
- If the request contains `request_uri`, fetches the Authorization Request from that URI
- Validates the incoming request with wallet capabilities
- Returns the validated `AuthorizationRequest` object

**Client validation:**
- For `pre-registered` clients: validates against `WalletConfig.trustedVerifiers`
- Can be disabled by setting `WalletConfig.validateTrustedVerifier` to `false` in wallet config

```swift
let authorizationRequest: AuthorizationRequest = try await openID4VP.authenticateVerifier(
    urlEncodedAuthorizationRequest: encodedAuthorizationRequest
)
```

###### Parameters

| Name                           | Type             | Required | Default Value | Description                               |
|--------------------------------|------------------|:---------|:--------------|-------------------------------------------|
| urlEncodedAuthorizationRequest | String           | Yes      | N/A           | URL Encoded VP Request from the Verifier. |


###### Example usage

**Scenario:** Authenticating a verifier from a QR code deeplink

```swift
 let authorizationRequest : AuthorizationRequest = try await openID4VP.authenticateVerifier(
                urlEncodedAuthorizationRequest: "openid4vp://authorize?client_id=...."
            )
```

###### Exceptions

- `DecodingException`: Issue while decoding the Authorization Request
- `InvalidQueryParams`: Missing or invalid query parameters, or both/neither of `presentation_definition` and `presentation_definition_uri` present
- `MissingInput`: Required parameters not present in the request
- `InvalidInput`: Required parameter values are empty
- `JWTVerification`: Error extracting public key, kid, or signature verification failure
- `InvalidData`: Request client_id/response_uri don't match trusted verifiers, unsupported response_mode, or missing client_metadata
- `UnsupportedPublicKeyType`: Public key type is not `publicKeyMultibase`
- `PublicKeyResolutionFailed`: Error extracting public key from verification method
- `InvalidVerifier`: Request client_id/response_uri don't match any trusted verifiers

**Note:** The SDK automatically sends error notifications to the Verifier's response_uri when applicable.

### `authenticateVerifier` - Additional Overload

In addition to accepting a URL-encoded Authorization Request, `authenticateVerifier` also provides an overload that accepts an already parsed Authorization Request as a dictionary.

This overload performs the same processing and validations as the URL-encoded variant, including:

* Verifier authentication and client validation
* Resolution of `request_uri` requests
* Authorization Request validation
* Validation against Wallet capabilities
* Trusted Verifier verification
* Returning a validated `AuthorizationRequest` object

###### Example Usage

```swift
let authorizationRequest: AuthorizationRequest = try await openID4VP.authenticateVerifier(
    authorizationRequest: [
        "client_id": "example-verifier",
        "response_type": "vp_token",
        "presentation_definition": [...]
    ]
)
```

###### Parameters

| Name                   | Type            | Required | Default Value | Description                                    |
|------------------------|-----------------|:--------:|:-------------:|------------------------------------------------|
| `authorizationRequest` | `[String: Any]` |   Yes    |      N/A      | Parsed VP Request represented as a dictionary. |

###### Returns

| Type                   | Description                                         |
|------------------------|-----------------------------------------------------|
| `AuthorizationRequest` | Fully validated and resolved Authorization Request. |

###### Exceptions

This overload throws the same exceptions as the URL-encoded variant.

## 2. User Selection of Credentials and Consent

After the Wallet successfully authenticates the Verifier and validates the OpenID4VP Authorization Request, the next step is to determine which credentials available in the Wallet satisfy the presentation requirements requested by the Verifier.  The Wallet should evaluate its stored credentials against the requested Presentation Definition or DCQL Query, present the matching credentials to the Wallet consumer, and obtain explicit consent before proceeding with presentation generation.

The SDK provides helper utilities for DCQL-based credential matching, allowing Wallet implementations to identify eligible credentials before displaying them to the user for selection.

> **Note:** The SDK currently provides credential matching support only for DCQL-based Authorization Requests through `DCQLHelper`. For Authorization Requests containing a Presentation Definition, credential matching and constraint evaluation must be implemented by the Wallet application based on its credential storage and presentation logic.

### DCQL Credential Matching

For Authorization Requests containing a DCQL query, the SDK provides the `DCQLHelper` utility to evaluate Wallet credentials against the requested constraints. The helper performs credential matching based on the supplied DCQL query and returns all credentials that satisfy the requested conditions.

You can obtain the DCQL query from a validated `AuthorizationDcqlRequest` and use it to identify matching credentials before prompting the user for selection and consent.

### `DCQLHelper`

`DCQLHelper` provides functionality for evaluating Wallet credentials against a DCQL query.

#### Parameters

| Name             | Type                      | Required | Default Value | Description                                                                                                                                                                                              |
|------------------|---------------------------|:--------:|:-------------:|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `jsonLdExpander` | `JsonLdExpanderCallback?` |    No    |     `nil`     | Optional callback used to expand JSON-LD credentials before DCQL evaluation. This is required when the Wallet credentials are JSON-LD based as credential matching depends on expanded JSON-LD contexts. |

#### Example Usage

```swift
import OpenID4VP

let dcqlHelper = DCQLHelper(jsonLdExpander: jsonLdExpanderCallback)
```

### `getMatchingCredentials`

Evaluates a collection of Wallet credentials against a DCQL query and returns the credentials that satisfy the requested constraints. This method should typically be invoked after receiving a validated `AuthorizationDcqlRequest` and before presenting credentials to the Wallet consumer for selection.

#### Method Signature

```swift
public func getMatchingCredentials(
    inputCredentials: [Credential],
    dcqlQuery: DCQLQuery
) async throws -> MatchingCredentialsResult
```

### Usage in Credential Matching

The Wallet passes its available credentials as input to credential matching:

```swift
let matchingResult = try await dcqlHelper.getMatchingCredentials(
    inputCredentials: walletAvailableCredentials,
    dcqlQuery: dcqlQuery
)
```

The SDK evaluates each `Credential` against the DCQL query constraints and returns the credentials that satisfy the requested requirements.

> **Note:** Credentials the SDK would be unable to present are excluded from the results, so that they are never offered to the user for selection. This currently applies to W3C VC Data Model `2.0` credentials whose holder key is neither Ed25519 nor P-256, and only for queries where `require_cryptographic_holder_binding` is `true` — a query which does not require holder binding is presented as a bare credential with no proof, so no holder key is involved. If a query's every candidate is excluded this way, it reports `cryptographic_holderbinding_or_meta_filter_mismatch`.

#### Parameters

| Name               | Type           | Required | Default Value | Description                                                                                        |
|--------------------|----------------|:--------:|:-------------:|----------------------------------------------------------------------------------------------------|
| `inputCredentials` | `[Credential]` |   Yes    |      N/A      | Collection of credentials available in the Wallet that should be evaluated against the DCQL query. |
| `dcqlQuery`        | `DCQLQuery`    |   Yes    |      N/A      | DCQL query extracted from the validated Authorization Request.                                     |

#### Returns

**Type:** `MatchingCredentialsResult`

The API returns a result object that contains matching credentials organized by query ID, along with credential set grouping information for UI presentation.

##### Top-level Fields

| Field            | Type                            | Description                                                                                                                                             |
|------------------|---------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| `success`        | `Boolean`                       | Overall success of the credential matching process. If `false`, an error should be sent to the verifier indicating missing credentials or claims.       |
| `queryMatches`   | `Map<String, QueryMatchResult>` | Map of query IDs to their individual match results                                                                                                      |
| `credentialSets` | `List<CredentialSetQuery>`      | Defines how credential sets are grouped and whether they are required. Used by the wallet UI to display credentials in a structured, user-friendly way. |

##### `queryMatches` — Per Query Result

Each entry in `queryMatches` is keyed by a `queryId` and contains:

| Field                      | Type                       | Optional | Description                                                                                                                        |
|----------------------------|----------------------------|:--------:|------------------------------------------------------------------------------------------------------------------------------------|
| `matchingCredentials`      | `List<MatchingCredential>` |   Yes    | List of credentials that match the query. Each entry contains a `credentialId` and `matchingClaims`.                               |
| `failedClaims`             | `List<ClaimFailure>`       |   Yes    | Populated only when no matching credentials are found. Contains the claim path and reason for failure.                             |
| `allowMultipleCredentials` | `Boolean`                  |   Yes    | Available when `matchingCredentials` are present. Indicates whether multiple matching credentials can be shared for this query ID. |

> **Note:** `matchingCredentials` and `failedClaims` are mutually exclusive — only one will be populated per query entry.

##### `credentialSets` — Credential Set Grouping

Each entry in `credentialSets` defines a group of credential options:

| Field      | Type                  | Description                                                                                                         |
|------------|-----------------------|---------------------------------------------------------------------------------------------------------------------|
| `options`  | `List<List<queryId>>` | List of options. If more than one element, the set is sectionized (i.e., any one of the options must be satisfied). |
| `required` | `Boolean`             | Whether this credential set is mandatory.                                                                           |

**Important:** `credentialSets` is always populated by the SDK, even if the original DCQL query does not include a `credential_sets` field. In such cases, the SDK automatically derives `credentialSets` from the queries, treating each query as a separate required credential set.

##### Example Response Structure

```json
{
  "success": false,
  "queryMatches": {
    "queryId1": {
      "matchingCredentials": [
        { 
          "credentialId": "matchingCredential1", 
          "matchingClaims": [
            {"path": ["credentialSubject", "family_name"]}, 
            {"path": ["credentialSubject", "given_name"]}
          ] 
        }
      ],
      "allowMultipleCredentials": true
    },
    "queryId2": {
      "failedClaims": [
        { "claim": {"path": ["credentialSubject", "address"]}, "reason": "CLAIM_UNAVAILABLE" },
        { "claim": {"path": ["credentialSubject", "dateOfBirth"]}, "reason": "CLAIM_VALUE_NOT_MATCHING" }
      ]
    }
  },
  "credentialSets": [
    { "options": [["queryId1"]], "required": true },
    { "options": [["queryId2"]], "required": true }
  ]
}
```

##### Credential Set Example - DCQL query without credential_sets

Given a DCQL query:

```json
{
  "credentials": [
    { "id": "nationalId", "format": "ldp_vc" },
    { "id": "dateOfBirth", "format": "ldp_vc" }
  ]
}
```

The SDK automatically populates `credentialSets` as:

```json
{
  "credentialSets": [
    { "options": [["nationalId"]], "required": true },
    { "options": [["dateOfBirth"]], "required": true }
  ]
}
```

##### SDK Consumer Iteration Logic

The wallet should process the `MatchingCredentialsResult` as follows:

1. **Check `success` flag:**
   - **If `true`:** Proceed with credential selection flow
   - **If `false`:** Show UI indicating not all required credentials are available. Iterate over `queryMatches` to find `failedClaims` and display reasons if needed. Send error to verifier via `sendErrorInfoToVerifier(...)`.

2. **Iterate `credentialSets`:** For each credential set:
   - **Check `required` flag:** Mark as "Required" or "Optional" in UI
   - **Check `options`:**
     - **If only one element:**
       - Get the query IDs from that element
       - Identify the `matchingCredentials` for those query IDs from `queryMatches`
       - Show to user for consent/selection
       - If `allowMultipleCredentials` is `false`, ensure user selection doesn't violate the single-credential constraint
     - **If more than one element (option):**
       - Show each element as a separate option
       - Prompt user to choose one option for this credential set
       - For selected section, get the query IDs and show matching credentials for user consent/selection

> **Note on `claimSets`:** The wallet should return the first option it can satisfy, as that is the preferred option from the Verifier. The SDK considers this when checking for matching claims and populates `matchingClaims` as per the first matching claim set.

#### Example Usage with Authorization Request

```swift
guard let dcqlRequest = authorizationRequest as? AuthorizationDcqlRequest else {
    // Handle Presentation Definition related matching credentials
}

let dcqlHelper = DCQLHelper(jsonLdExpander: jsonLdExpanderCallback)

let matchingResult = try await dcqlHelper.getMatchingCredentials(
    inputCredentials: walletAvailableCredentials,
    dcqlQuery: dcqlRequest.dcqlQuery
)
```

#### Credential Structure

`Credential` represents a Verifiable Credential stored in the Wallet and is used as an input when evaluating presentation requirements, such as DCQL queries. The Wallet provides its available credentials in this format to the SDK helper methods (`DCQLHelper.getMatchingCredentials`) to determine which credentials satisfy the Verifier's request.

A `Credential` contains the credential format, the credential payload, and a unique identifier that allows the Wallet to track and manage the credential.

##### Parameters

| Name           | Type         | Required | Default Value | Description                                                                                                                                                                                |
|----------------|--------------|:--------:|:-------------:|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `format`       | `FormatType` |   Yes    |      N/A      | Specifies the format of the credential. The format determines how the credential is represented and processed during presentation. Examples include `ldp_vc`, `mso_mdoc`, and `dc_sd_jwt`. |
| `data`         | `AnyCodable` |   Yes    |      N/A      | Contains the credential payload in a format-specific representation. The Wallet should provide the complete credential data required for evaluation and presentation generation.           |
| `credentialId` | `String`     |   Yes    |      N/A      | Unique identifier assigned to the credential by the Wallet. This identifier is used to reference the credential during matching.                                                           |

##### Credential Format Handling

The `data` field is format-specific and should contain the credential in its native representation:

| Credential Format | `data` Representation                         | Additional Requirements                                                                      |
|-------------------|-----------------------------------------------|----------------------------------------------------------------------------------------------|
| `ldp_vc`          | JSON-LD Verifiable Credential object          | Requires JSON-LD processing support when matching depends on expanded JSON-LD contexts.      |
| `mso_mdoc`        | Mobile Security Object (mDoc) credential data | Should contain the data required for ISO/IEC 18013-5 presentation processing.                |
| `dc_sd_jwt`       | SD-JWT credential representation              | Should contain the full SD-JWT credential data required for selective disclosure processing. |


### Wallet Responsibilities

* Maintaining the credential store.
* Providing credentials in the expected Credential structure.
* Ensuring credential data is complete and valid for the declared format.
* Handling user selection and consent before sharing credentials.
* Providing selected credentials for Verifiable Presentation construction.

Once the Wallet consumer has selected the credentials and granted consent, the selected credentials can be used to construct the Verifiable Presentation and continue the OpenID4VP presentation flow.

## 3. Construction of a Verifiable Presentation and Submission to the Verifier

Once the user has selected the credentials and provided consent for sharing them, the Wallet constructs a Authorization Response and submits it to the Verifier.

The VP construction process begins with preparing the unsigned data that must be signed by the Wallet. This step is common across all Authorization Response construction flows and is performed using the `constructUnsignedVPToken` method.

After the unsigned data has been signed, the SDK supports two different approaches:

1. **Authorization Response Construction and Submission** - `sendVPResponseToVerifier`

    * The signed data is provided back to the SDK.
    * The SDK constructs the Verifiable Presentation and generates the Authorization Response.
    * The SDK then submits the Authorization Response to the Verifier.

2. **Authorization Response Construction Only** - `constructVPResponse`

    * The signed data is provided back to the SDK.
    * The SDK constructs the Verifiable Presentation and generates the Authorization Response.
    * The Authorization Response is returned to the SDK consumer, who is responsible for submitting it to the Verifier.

### Prepare Data for VP Construction — `constructUnsignedVPToken`

This method generates a flattened list of unsigned data (`UnsignedVPToken`) from the selected Verifiable Credentials. By providing all required signing information upfront, this method simplifies the signing workflow for each VP token.

```swift
let unsignedVPTokens: [UnsignedVPToken] = try await openID4VP.constructUnsignedVPToken(
    selectedCredentials: [String: [Credential]]
)
```

#### Error Handling: 

Any failure encountered during this phase results in an OAuth error response being returned to the Verifier.

```json
{
  "error": "server_error",
  "error_description": "The wallet encountered an internal error while preparing the presentation."
}
```

#### Request Parameters

| Name                | Type                   | Required | Description                                                                                                                                                         |
|---------------------|------------------------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| selectedCredentials | [String: [Credential]] | Yes      | Map of credential query IDs or input descriptor IDs to credential lists. For understanding Credential structure refer [Credential Structure](#credential-structure) |


> **Note:**
>
> * When using selectively disclosable credentials, only the claims selected for disclosure to the Verifier should be included in the credentials passed to the SDK for VP construction.
> * The Wallet must ensure that a valid credential is provided for each credential query ID (or input descriptor ID) that it intends to satisfy as part of the presentation.


#### Response Parameters

Each `UnsignedVPToken` in the returned array contains:

| Property           | Type       | Description                                                                                                                                                                  |
|--------------------|------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id                 | String     | Unique Identifier for the Unsigned VP Token                                                                                                                                  |
| format             | FormatType | Credential format (ldp_vc, mso_mdoc, vc+sd-jwt, dc+sd-jwt)                                                                                                                   |
| holderKeyReference | String     | Reference to holder's key. The identified holder key reference can be used by the Consumer of the SDK to locate the corresponding private key and sign the VP token payload. |
| signatureAlgorithm | String     | Signature algorithm to be used (e.g., ES256)                                                                                                                                 |
| dataToSign         | Data       | Payload data that must be signed                                                                                                                                             |

#### Example usage

```swift
let unsignedVPTokens: [UnsignedVPToken] = try await openID4VP.constructUnsignedVPToken(
    selectedCredentials: [
        "input_descriptor_id_1": [
           Credential(...)
        ],
    ]
)

// The wallet can now iterate through unsignedVPTokens and sign each one
let signingResults = try unsignedVPTokens.map { unsignedVPToken in
    let signature = try signData(
        unsignedVPToken.dataToSign,
        keyReference: unsignedVPToken.holderKeyReference,
        algorithm: unsignedVPToken.signatureAlgorithm
    )
    return VPTokenSigningResult(id: unsignedVPToken.id, signedData: signature)
}
```

#### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the vp_token without proof.
2. InvalidData exception is thrown if:
    - Provided verifiable credentials list is empty
    - No mapping found for a specific credential format
    - Invalid credential structure


### Prepare Authorization Response — `constructVPResponse`

This method generates an Authorization Response based on the `response_type` and `response_mode` defined in the Verifiable Presentation Request. 
The provided signed data (`VPTokenSigningResult`) is embedded into the response, and the resulting Authorization Response payload is returned to the caller for subsequent handling.



```swift
let vpResponse: [String: Any] = openID4VP.constructVPResponse(
    vpTokenSigningResults: vpTokenSigningResults
)
```

#### Error Handling:

Any failure encountered during this phase results in an OAuth error response being returned to the Verifier.

```json
{
  "error": "server_error",
  "error_description": "The wallet encountered an internal error while preparing the authorization response."
}
```

#### Parameters

| Name                  | Type                   | Required | Description                                                        |
|-----------------------|------------------------|----------|--------------------------------------------------------------------|
| vpTokenSigningResults | [VPTokenSigningResult] | Yes      | List of signing results matching `constructUnsignedVPToken` output |

**`VPTokenSigningResult` Structure**

The `VPTokenSigningResult` contains the signed data required for Authorization Response construction.

| Field        | Type     | Description                                                                                                                                                                                                            |
|--------------|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `id`         | `String` | Unique identifier of the Verifiable Presentation. This value must match the `id` present in the corresponding unsignedVPToken, as it serves as the linkability factor between the unsigned and signed representations. |
| `signedData` | `Data`   | The cryptographic signature generated over the `dataToBeSigned` payload using the selected signing algorithm and key reference.                                                                                        |


#### Response Parameters

| Type           | Description                                                                                           |
|----------------|-------------------------------------------------------------------------------------------------------|
| [String : Any] | Dictionary containing the constructed Authorization response as per response type and `response_mode` |

#### Example usage

```swift
let vpResponse: [String: Any] = openID4VP.constructVPResponse(
    vpTokenSigningResults: vpTokenSigningResults
)
```

#### Exceptions

- `JsonEncodingFailed`: Issue serializing the vp_token or presentation_submission
- `InvalidData`: Unsupported response_type in the authorization request

### Prepare and submit Authorization Response to Verifier - `sendVPResponseToVerifier`

This method generates an Authorization Response in accordance with the `response_type` and `response_mode` specified in the Verifiable Presentation Request. It embeds the signed data provided through the `VPTokenSigningResult` input, submits the resulting Authorization Response to the Verifier, and returns the Verifier's response.

```swift
let response: VerifierResponse = try await openID4VP.sendVPResponseToVerifier(
    vpTokenSigningResults: vpTokenSigningResults
)
```

#### Error Handling:

Any failure encountered during this phase results in an OAuth error response being returned to the Verifier.

```json
{
  "error": "server_error",
  "error_description": "The wallet encountered an internal error while preparing the authorization response."
}
```

###### Parameters

| Name                  | Type                   | Required | Description                                                 |
|-----------------------|------------------------|----------|-------------------------------------------------------------|
| vpTokenSigningResults | [VPTokenSigningResult] | Yes      | List of signing results matching `constructUnsignedVPToken` |

**`VPTokenSigningResult` Structure**

The `VPTokenSigningResult` contains the signed data required for Authorization Response construction.

| Field        | Type     | Description                                                                                                                                                                                                            |
|--------------|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `id`         | `String` | Unique identifier of the Verifiable Presentation. This value must match the `id` present in the corresponding unsignedVPToken, as it serves as the linkability factor between the unsigned and signed representations. |
| `signedData` | `Data`   | The cryptographic signature generated over the `dataToBeSigned` payload using the selected signing algorithm and key reference.                                                                                        |

#### Response - VerifierResponse Structure

| Property         | Type          | Description                                      |
|------------------|---------------|--------------------------------------------------|
| statusCode       | Int           | HTTP status code from the Verifier               |
| redirectUri      | String        | URI to redirect user after response submission   |
| additionalParams | [String: Any] | Additional response parameters from the Verifier |
| headers          | [String: Any] | Response headers from the Verifier               |

###### Example usage

```swift
let response: VerifierResponse = try await openID4VP.sendVPResponseToVerifier(
    vpTokenSigningResults: vpTokenSigningResults
)
```

###### Exceptions

- `JsonEncodingFailed`: Issue serializing vp_token or presentation_submission
- `UnsupportedTypeDecoding`: Error decoding unsupported types
- `InterruptedIOException`: Connection timeout
- `NetworkRequestFailed`: HTTP POST request failure
- `InvalidData`: Unsupported response_type

## 4. Dispatch Errors to the Verifier

If an error occurs during the OpenID4VP flow, an error response should be returned to the Verifier. The SDK provides methods to construct and dispatch these error responses.

The SDK automatically handles and sends errors that occur internally during:

* OpenID4VP request validation
* Authorization Response construction

Only errors that require user interaction or application-specific handling by the Wallet or SDK consumer should be explicitly passed to the methods described below.

### Construct Authorization Error Response — `constructErrorInfo`

Constructs an OAuth/OpenID4VP-compliant error response from an exception, based on the `response_mode` specified in the VP Request.

```swift
let errorResponse: [String: Any] = openID4VP.constructErrorInfo(exception: error)
```

#### Exceptions

* `ErrorDispatchFailure` — Thrown if the error response cannot be prepared for dispatch to the Verifier.

### Send Authorization Error Response to the Verifier — `sendErrorInfoToVerifier`

Sends an error response to the Verifier for errors that must be handled by the Wallet or SDK consumer during the OpenID4VP flow.

This method:

* Constructs the appropriate error response from the provided exception.
* Sends the error response to the Verifier.
* Returns the response received from the Verifier.

For details about the returned value, see the [VerifierResponse structure](#response---verifierresponse-structure).

```swift
// Example: User declined to share credentials
let verifierResponse: VerifierResponse = try await openID4VP.sendErrorInfoToVerifier(
    error: AccessDenied(
        message: "User did not consent to share the requested credentials.",
        className: "WalletApp"
    )
)
```

#### Exceptions

* `ErrorDispatchFailure` — Thrown if the error response cannot be successfully delivered to the Verifier.

---

## Illustrative Swift Integration Skeleton

**Scenario:** Complete end-to-end OpenID4VP flow handling both DCQL and Presentation Exchange requests

```swift
import Foundation
import OpenID4VP

func handleOVPFlow(
    applicationId: String,
    
    encodedAuthorizationRequest: String,
    
    trustedVerifiers: [Verifier],
    /*...Other wallet configurations..*/
    
    walletAvailableCredentials: [Credential]
) async throws -> Void {
    let walletConfig = WalletConfig(trustedVerifiers: trustedVerifiers, /*...Other wallet configurations..*/)
    let credentialById = Dictionary(uniqueKeysWithValues: walletAvailableCredentials.map { ($0.credentialId, $0) })

    let openID4VP = OpenID4VP(
        traceabilityId: applicationId,
        walletConfig: walletConfig,
        jsonLdCanonicalizer: jsonLdCanonicalizerCallback // Optional callback; required when processing W3C credentials that need JSON-LD canonicalization.
    )

    do {
        let validatedVPRequest = try await openID4VP.authenticateVerifier(
            urlEncodedAuthorizationRequest: encodedAuthorizationRequest
        )

        var selectedCredentials: [String: [Credential]] = [:]
            

        if let vpRequest = validatedVPRequest as? AuthorizationDcqlRequest {
            // DCQL flow
            let dcqlHelper = DCQLHelper(jsonLdExpander: jsonLdExpanderCallback)
            let matchingVcsResult = try await dcqlHelper.getMatchingCredentials(
                inputCredentials: walletAvailableCredentials,
                dcqlQuery: vpRequest.dcqlQuery
            )
            let result = getShareableCredentialsWithConsent(matchingVcsResult)
            
            if(result.userConsentRejected) {
                let vpRejectionVerifierResponse = try await openID4VP.sendErrorInfoToVerifier(error: AccessDenied(message: "User rejected to share credentials", className: "SampleWalletApp"))
                handleVeriferResponse(vpRejectionVerifierResponse)
                return
            } else {
                selectedCredentials = result.selectedCredentials
            }
        } else if let vpRequest = validatedVPRequest as? AuthorizationPresentationExchangeRequest {
            // Presentation Exchange flow
            let result = getCredentialsForVPRequestWithConsent(vpRequest)
            
            if(result.userConsentRejected) {
                let vpRejectionVerifierResponse = try await openID4VP.sendErrorInfoToVerifier(error: AccessDenied(message: "User rejected to share credentials", className: "SampleWalletApp"))
                handleVeriferResponse(vpRejectionVerifierResponse)
                return
            } else {
                selectedCredentials = result.selectedCredentials
            }
        } else {
            // Unexpected request type
            let vpRejectionVerifierResponse = try await openID4VP.sendErrorInfoToVerifier(error: InvalidData(message: "Unexpected request type", className: "SampleWalletApp"))
            handleVeriferResponse(vpRejectionVerifierResponse)
            return
        }

        let unsignedVpTokens = try await openID4VP.constructUnsignedVPToken(
            selectedCredentials: selectedCredentials
        )
        
        let signingResults = try unsignedVpTokens.map { unsignedVPToken in
            let signature = try signData(
                unsignedVPToken.dataToSign,
                keyReference: unsignedVPToken.holderKeyReference,
                algorithm: unsignedVPToken.signatureAlgorithm
            )
            return VPTokenSigningResult(id: unsignedVPToken.id, signedData: signature)
        }

        let vpSubmissionVerifierResponse = try await openID4VP.sendVPResponseToVerifier(
            vpTokenSigningResults: signingResults
        )
        handleVeriferResponse(vpSubmissionVerifierResponse)
    } catch {
       // Show error screen as per error -> error.errorCode / error.message and handle verifier response if available -> error.verifierResponse
    }
}


// Helpers

func jsonLdCanonicalizerCallback(_ data: String) async throws -> String {
    // 1. Parse the input JSON string into a data structure - unsignedVP

    guard let jsonData = data.data(using: .utf8),
          var unsignedVP = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any]
    else {
        // handle error
        return ""
    }

    // 2. Extract @context
    let context = unsignedVP["@context"]

    // 3. Extract proof and attach context
    var jsonLdProof: [String: Any] = [:]
    if let proof = unsignedVP["proof"] as? [String: Any] {
        jsonLdProof = proof
        jsonLdProof["@context"] = context ?? NSNull()
    }

    // 4. Remove proof from VP
    var jsonldObjectClone = unsignedVP
    jsonldObjectClone.removeValue(forKey: "proof")

    func toJSONString(_ obj: Any) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
        guard let str = String(data: data, encoding: .utf8) else {
            // handle error
            return ""
        }
        return str
    }

    func jsonldCanonize(_ obj: Any) async throws -> String {
        // Implement your JSON-LD canonicalization logic here
        // For demonstration, we are just returning empty string
        return ""
    }
    func sha256(_ input: Data) -> Data {
        // Implement SHA-256 hashing of the input data
        // For demonstration, we are just returning the input data. Replace this with actual hashing logic.
        return input
    }
    func base64urlEncode(_ input: Data) -> String {
        // Implement your base64URL encoding logic here
        // For demonstration, we are just returning empty string
        return ""
    }

    // 5. Canonicalize unsignedVP
    let normalizedJsonldObject = try await jsonldCanonize(jsonldObjectClone)

    // 6. Canonicalize jsonLdProof
    let normalizedJsonldProof = try await jsonldCanonize(jsonLdProof)

    // 7. Combine hashes (SHA-256)
    let proofHash = sha256(Data(normalizedJsonldProof.utf8))
    let objectHash = sha256(Data(normalizedJsonldObject.utf8))
    var hashData = Data()
    hashData.append(proofHash)
    hashData.append(objectHash)


    return base64urlEncode(hashData)
}

func jsonLdExpanderCallback(_ data: [String: Any]) async throws -> [String: Any] {
    // Implement your JSON-LD expansion logic here
    // 1. Take the input data and expand it according to the JSON-LD context and rules
    // For demonstration, we are just returning the input data
    return data
}

func getShareableCredentialsWithConsent(_ matchingVcsResult: MatchingCredentialsResult) -> (selectedCredentials: [String: [Credential]], userConsentRejected: Bool) {
    // Implement your logic to filter and select credentials based on user consent
    // 1. Take the matchingVcsResult which contains the credentials that match the DCQL query
    // 2. Present these credentials to the user and ask for their consent to share them with the verifier
    // 3. Based on the user's consent, filter the credentials and return only those that the user has agreed to share
    // For demonstration, we are just returning empty map here and consent as not rejected
    return ([:], false)
}

func getCredentialsForVPRequestWithConsent(_ vpRequest: AuthorizationPresentationExchangeRequest) -> (selectedCredentials: [String: [Credential]], userConsentRejected: Bool) {
    // Implement your logic to filter available wallet credentials based on the requirements in the VP request, select credentials and get user consent
    // For demonstration, we are just returning empty map here and consent as not rejected
    return ([:], false)
}

func signData(_ data: Data, keyReference: String, algorithm: String) throws -> Data {
    // Implement your signing logic here
    return Data()
}

func handleVeriferResponse(_ verifierResponse: VerifierResponse) -> Void {
    // Implement your logic to handle the response from the verifier after sending the VP response
    // Show successful submission message to the user if the response indicates success, otherwise show an error message
    // redirect to verifierResponse.redirectUri if available
}
```

Notes:
- The crypto implementations like signing data is kept in your wallet app while the SDK focuses on VP request validation/VP response construction and sending to Verifier.

---

## Appendix: Key Swift Types and Entry Points

The following files contain the primary types and APIs used throughout the SDK:

* **Entry point**
    * `Sources/OpenID4VP/OpenID4VP.swift`
* **Wallet configuration and credential models**
    * `Sources/OpenID4VP/Wallet/WalletConfig.swift`
    * `Sources/OpenID4VP/Wallet/Credential.swift`
* **DCQL utilities**
    * `Sources/OpenID4VP/Helpers/DCQLHelper.swift`
* **Signing work units**
    * `Sources/OpenID4VP/AuthorizationResponse/UnsignedVPToken/UnsignedVPToken.swift`
    * `Sources/OpenID4VP/AuthorizationResponse/VPTokenSigningResult/VPTokenSigningResult.swift`
* **Callback type definitions**
    * `Sources/OpenID4VP/Constants/CallbackTypes.swift`
