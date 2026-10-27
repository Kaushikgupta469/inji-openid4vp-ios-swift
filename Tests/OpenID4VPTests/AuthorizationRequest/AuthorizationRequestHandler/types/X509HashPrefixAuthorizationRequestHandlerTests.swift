import Foundation
import CryptoKit
import Security
import SwiftASN1
import X509
import XCTest
@testable import OpenID4VP

private let dayInSeconds: TimeInterval = 24 * 60 * 60
private let requestUriString = "https://mock-verifier.com/verifier/get-auth-request-obj"

class X509HashPrefixAuthorizationRequestHandlerTests: XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseDispatchInfo: (ResponseDispatchInfo) -> Void = { _ in }
    let walletNonce = "qPmxiNFCR3QTm19POc8u"
    let verifier = X509HashTestData.createVerifierCredential()

    private var walletConfig: WalletConfig!

    override func setUpWithError() throws {
        walletConfig = makeWalletConfig()
    }

    override func tearDownWithError() throws {
        mockNetworkManager.clearResponses()
    }

    func testShouldProcessAValidRequestPassedByValue() async throws {
        let authorizationRequest = try await createHandler(requestByValue()).handle()

        XCTAssertTrue(authorizationRequest is AuthorizationDcqlRequest)
        XCTAssertEqual(verifier.clientId, authorizationRequest.clientId)
    }

    func testShouldProcessAValidRequestPassedByReferenceWithRequestUriMethodPost() async throws {
        mockNetworkManager.setMockResponse(
            for: requestUriString,
            responseBody: signedRequestObject(payload: X509HashTestData.requestObjectPayload(clientId: verifier.clientId, walletNonce: walletNonce))
        )
        let parameters: [String: Any] = [
            AuthorizationRequestFieldConstants.clientId: verifier.clientId,
            AuthorizationRequestFieldConstants.requestUri: requestUriString,
            AuthorizationRequestFieldConstants.requestUriMethod: "post"
        ]

        let authorizationRequest = try await createHandler(parameters).handle()

        XCTAssertEqual(verifier.clientId, authorizationRequest.clientId)
        let requestBody = mockNetworkManager.recordedRequests[requestUriString]?.requestBody
        XCTAssertEqual(walletNonce, requestBody?["wallet_nonce"])
        let walletMetadata = try XCTUnwrap(requestBody?["wallet_metadata"])
        XCTAssertTrue(walletMetadata.contains("\"client_id_prefixes_supported\":[\"x509_hash\"]"), walletMetadata)
        XCTAssertTrue(walletMetadata.contains("\"request_object_signing_alg_values_supported\":[\"ES256\",\"EdDSA\"]"), walletMetadata)
    }

    func testShouldProcessAValidRequestSignedWithEdDSAByAnEd25519LeafCertificate() async throws {
        let ed25519Verifier = X509HashTestData.createVerifierCredential(keyType: .ed25519)

        let authorizationRequest = try await createHandler(
            requestByValue(signedRequestObject(credential: ed25519Verifier, alg: "EdDSA"), clientId: ed25519Verifier.clientId)
        ).handle()

        XCTAssertEqual(ed25519Verifier.clientId, authorizationRequest.clientId)
    }

    func testShouldRouteAnX509HashClientIdReceivedInTheAuthorizationRequestUrlToThisHandler() async throws {
        let encodedClientId = verifier.clientId.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        let authorizationRequestUrl = "openid4vp://authorize?client_id=\(encodedClientId)&request=\(signedRequestObject())"

        let authorizationRequest = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
            urlEncodedAuthorizationRequest: authorizationRequestUrl,
            walletConfig: walletConfig,
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: walletNonce,
            networkManager: mockNetworkManager
        )

        XCTAssertEqual(verifier.clientId, authorizationRequest.clientId)
    }

    func testShouldRejectTheRequestWhenX509HashIsNotSupportedByTheWallet() async {
        walletConfig = makeWalletConfig(clientIdPrefixesSupported: [.decentralizedIdentifier])

        await XCTAssertAsyncThrowsError(try await createHandler(requestByValue()).handle()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "client_id_prefix x509_hash is not supported by wallet",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testShouldRejectAClientIdWhoseValueIsNotABase64UrlEncodedSha256Hash() async {
        let sha256Hex = SHA256.hash(data: derEncodedCertificate(verifier.certificate)).map { String(format: "%02x", $0) }.joined()
        let malformedClientIds = ["x509_hash:", "\(verifier.clientId)=", "\(verifier.clientId)\n", "x509_hash:\(sha256Hex)"]

        for clientId in malformedClientIds {
            await XCTAssertAsyncThrowsError(
                try await createHandler(requestByValue(signedRequestObject(clientId: clientId), clientId: clientId)).handle()
            ) { error in
                assertOpenID4VPException(error,
                                         expectedMessage: "client_id must be x509_hash:<base64url-encoded SHA-256 hash of the leaf certificate>",
                                         expectedCode: OpenID4VPErrorCodes.invalidRequest)
            }
        }
    }

    func testShouldRejectAnUnsignedRequest() async {
        await XCTAssertAsyncThrowsError(
            try await createHandler([AuthorizationRequestFieldConstants.clientId: verifier.clientId]).handle()
        ) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "unsigned request is not supported for given client_id_prefix - x509_hash",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testShouldRejectTheRequestWhenTheTypHeaderIsNotOauthAuthzReqJwt() async {
        var header = X509HashTestData.requestObjectHeader(verifier)
        header["typ"] = "JWT"

        await assertRequestObjectRejected(
            signedRequestObject(header: header),
            expectedMessage: "Invalid typ in JWS header. Expected 'oauth-authz-req+jwt', found 'JWT'"
        )
    }

    func testShouldRejectTheRequestWhenTheSigningAlgorithmIsNotSupported() async {
        await assertRequestObjectRejected(
            signedRequestObject(alg: "ES384"),
            expectedMessage: "request_object_signing_alg is not supported by wallet"
        )
    }

    func testShouldRejectARequestByValueSignedWithES256WhenTheWalletAllowsOnlyEdDSA() async {
        walletConfig = makeWalletConfig(requestObjectSigningAlgValuesSupported: [.edDsa])

        await assertRequestObjectRejected(signedRequestObject(), expectedMessage: "request_object_signing_alg is not supported by wallet")
    }

    func testShouldRejectARequestByValueSignedWithEdDSAWhenTheWalletAllowsOnlyES256() async {
        walletConfig = makeWalletConfig(requestObjectSigningAlgValuesSupported: [.es256])
        let ed25519Verifier = X509HashTestData.createVerifierCredential(keyType: .ed25519)

        await assertRequestObjectRejected(
            signedRequestObject(credential: ed25519Verifier, alg: "EdDSA"),
            expectedMessage: "request_object_signing_alg is not supported by wallet",
            clientId: ed25519Verifier.clientId
        )
    }

    func testShouldRejectARequestByValueWhenTheWalletAllowsNoRequestObjectSigningAlgorithms() async {
        walletConfig = makeWalletConfig(requestObjectSigningAlgValuesSupported: nil)

        await assertRequestObjectRejected(signedRequestObject(), expectedMessage: "request_object_signing_alg is not supported by wallet")
    }

    func testShouldRejectTheRequestWhenX5cIsMissingOrEmpty() async {
        var headerWithoutX5c = X509HashTestData.requestObjectHeader(verifier)
        headerWithoutX5c.removeValue(forKey: "x5c")
        var headerWithEmptyX5c = X509HashTestData.requestObjectHeader(verifier)
        headerWithEmptyX5c["x5c"] = [String]()

        for header in [headerWithoutX5c, headerWithEmptyX5c] {
            await assertRequestObjectRejected(
                signedRequestObject(header: header),
                expectedMessage: "x5c certificate chain is missing in the JWS header"
            )
        }
    }

    func testShouldRejectTheRequestWhenTheClientIdIsNotTheHashOfTheLeafCertificate() async {
        let otherVerifier = X509HashTestData.createVerifierCredential()

        await assertRequestObjectRejected(
            signedRequestObject(clientId: otherVerifier.clientId),
            expectedMessage: "client_id does not match the SHA-256 hash of the leaf certificate in x5c",
            clientId: otherVerifier.clientId
        )
    }

    func testShouldRejectTheRequestWhenX5cLeafIsNotACertificate() async {
        let notACertificate = Data("not a certificate".utf8)
        let clientId = "x509_hash:\(Data(SHA256.hash(data: notACertificate)).toBase64UrlEncoded())"
        var header = X509HashTestData.requestObjectHeader(verifier)
        header["x5c"] = [notACertificate.base64EncodedString()]

        await assertRequestObjectRejected(
            signedRequestObject(clientId: clientId, header: header),
            expectedMessage: "x5c[0] is not a valid DER-encoded X.509 certificate",
            clientId: clientId
        )
    }

    func testShouldRejectTheRequestWhenX5cLeafIsNotStandardBase64() async {
        // "-" is valid only in base64url
        var header = X509HashTestData.requestObjectHeader(verifier)
        header["x5c"] = ["-" + verifier.x5cEntry.dropFirst()]

        await assertRequestObjectRejected(
            signedRequestObject(header: header),
            expectedMessage: "x5c[0] must be a base64-encoded DER X.509 certificate"
        )
    }

    func testShouldRejectTheRequestWhenItIsNotSignedWithTheLeafCertificateKey() async {
        await XCTAssertAsyncThrowsError(
            try await createHandler(requestByValue(signedRequestObject(signingKey: .p256(P256.Signing.PrivateKey())))).handle()
        ) { error in
            let exception = error as? OpenID4VPException
            XCTAssertEqual(OpenID4VPErrorCodes.invalidRequestObject, exception?.errorCode)
            XCTAssertTrue(exception?.message.hasPrefix("Request URI response validation failed - ") == true, "\(error)")
        }
    }

    func testShouldRejectTheRequestWhenAlgDoesNotMatchTheLeafCertificateKey() async {
        await assertRequestObjectRejected(
            signedRequestObject(alg: "EdDSA"),
            expectedMessage: "Signing algorithm EdDSA does not match the leaf certificate key"
        )
    }

    func testShouldRejectTheRequestWhenTheLeafCertificateHasExpired() async {
        let expiredVerifier = X509HashTestData.createVerifierCredential(
            notValidBefore: Date() - 10 * dayInSeconds,
            notValidAfter: Date() - dayInSeconds
        )

        await assertRequestObjectRejected(
            signedRequestObject(credential: expiredVerifier),
            expectedMessage: "Leaf certificate in x5c has expired",
            clientId: expiredVerifier.clientId
        )
    }

    func testShouldRejectTheRequestWhenTheLeafCertificateIsNotYetValid() async {
        let notYetValidVerifier = X509HashTestData.createVerifierCredential(
            notValidBefore: Date() + dayInSeconds,
            notValidAfter: Date() + 10 * dayInSeconds
        )

        await assertRequestObjectRejected(
            signedRequestObject(credential: notYetValidVerifier),
            expectedMessage: "Leaf certificate in x5c is not yet valid",
            clientId: notYetValidVerifier.clientId
        )
    }

    func testShouldAcceptALeafCertificateIssuedByAnIntermediateCAThatChainsToTheTrustAnchor() async throws {
        let intermediateIssuedVerifier = X509HashTestData.createVerifierCredential(
            issuer: X509HashTestData.intermediateCertificateAuthority
        )

        let authorizationRequest = try await createHandler(
            requestByValue(signedRequestObject(credential: intermediateIssuedVerifier), clientId: intermediateIssuedVerifier.clientId)
        ).handle()

        XCTAssertEqual(2, intermediateIssuedVerifier.x5c.count)
        XCTAssertEqual(intermediateIssuedVerifier.clientId, authorizationRequest.clientId)
    }

    func testShouldAcceptAnIntermediateCAConfiguredAsTheTrustAnchor() async throws {
        walletConfig = makeWalletConfig(verifierTrustAnchors: [X509HashTestData.intermediateCertificateAuthority.x5cEntry])
        let intermediateIssuedVerifier = X509HashTestData.createVerifierCredential(
            issuer: X509HashTestData.intermediateCertificateAuthority
        )

        let authorizationRequest = try await createHandler(
            requestByValue(signedRequestObject(credential: intermediateIssuedVerifier), clientId: intermediateIssuedVerifier.clientId)
        ).handle()

        XCTAssertEqual(intermediateIssuedVerifier.clientId, authorizationRequest.clientId)
    }

    func testShouldAcceptAChainThatAlsoCarriesTheRootCACertificate() async throws {
        var header = X509HashTestData.requestObjectHeader(verifier)
        header["x5c"] = verifier.x5c + [X509HashTestData.rootCertificateAuthority.x5cEntry]

        let authorizationRequest = try await createHandler(requestByValue(signedRequestObject(header: header))).handle()

        XCTAssertEqual(verifier.clientId, authorizationRequest.clientId)
    }

    func testShouldAcceptALeafCertificateWithoutAKeyUsageExtension() async throws {
        let verifierWithoutKeyUsage = X509HashTestData.createVerifierCredential(keyUsage: nil)

        let authorizationRequest = try await createHandler(
            requestByValue(signedRequestObject(credential: verifierWithoutKeyUsage), clientId: verifierWithoutKeyUsage.clientId)
        ).handle()

        XCTAssertEqual(verifierWithoutKeyUsage.clientId, authorizationRequest.clientId)
    }

    func testShouldRejectTheRequestWhenNoTrustAnchorsAreConfigured() async {
        walletConfig = makeWalletConfig(verifierTrustAnchors: [])

        await assertRequestObjectRejected(
            signedRequestObject(),
            expectedMessage: "No trust anchors are configured to validate the x5c certificate chain"
        )
    }

    func testShouldRejectTheRequestWhenAConfiguredTrustAnchorIsNotACertificate() async {
        walletConfig = makeWalletConfig(verifierTrustAnchors: [X509HashTestData.rootCertificateAuthority.x5cEntry, "not a certificate"])

        await assertRequestObjectRejected(
            signedRequestObject(),
            expectedMessage: "verifierTrustAnchors[1] in the wallet configuration is not a base64-encoded DER X.509 certificate"
        )
    }

    func testShouldRejectALeafCertificateIssuedByACAThatIsNotATrustAnchor() async {
        let untrustedCertificateAuthority = X509HashTestData.createCertificateAuthority(
            commonName: "Other Root CA",
            organization: "Other Trust Services"
        )
        let untrustedVerifier = X509HashTestData.createVerifierCredential(issuer: untrustedCertificateAuthority)

        await assertRequestObjectRejectedAsUntrusted(signedRequestObject(credential: untrustedVerifier), clientId: untrustedVerifier.clientId)
    }

    func testShouldRejectAChainThatLeavesOutTheIntermediateCACertificate() async {
        let intermediateIssuedVerifier = X509HashTestData.createVerifierCredential(
            issuer: X509HashTestData.intermediateCertificateAuthority
        )
        var header = X509HashTestData.requestObjectHeader(intermediateIssuedVerifier)
        header["x5c"] = [intermediateIssuedVerifier.x5cEntry]

        await assertRequestObjectRejectedAsUntrusted(
            signedRequestObject(credential: intermediateIssuedVerifier, header: header),
            clientId: intermediateIssuedVerifier.clientId
        )
    }

    func testShouldRejectAChainWhoseIntermediateCACertificateHasExpired() async {
        let expiredCertificateAuthority = X509HashTestData.createCertificateAuthority(
            commonName: "Expired Issuing CA",
            issuer: X509HashTestData.rootCertificateAuthority,
            notValidBefore: Date() - 10 * dayInSeconds,
            notValidAfter: Date() - dayInSeconds
        )
        let expiredChainVerifier = X509HashTestData.createVerifierCredential(issuer: expiredCertificateAuthority)

        await assertRequestObjectRejectedAsUntrusted(
            signedRequestObject(credential: expiredChainVerifier),
            clientId: expiredChainVerifier.clientId
        )
    }

    func testShouldRejectALeafCertificateIssuedByAnotherVerifierCertificateThatIsNotACA() async throws {
        guard case .p256(let verifierPrivateKey) = verifier.signingKey else {
            return XCTFail("The default test Verifier has a P-256 key")
        }
        let verifierAsIssuer = TestCertificateAuthority(
            certificate: verifier.certificate,
            privateKey: verifierPrivateKey,
            issuer: X509HashTestData.rootCertificateAuthority
        )
        let impersonatingVerifier = X509HashTestData.createVerifierCredential(
            organization: "Other Bank",
            commonName: "Other Verifier",
            issuer: verifierAsIssuer
        )

        XCTAssertEqual(2, impersonatingVerifier.x5c.count)
        await assertRequestObjectRejectedAsUntrusted(
            signedRequestObject(credential: impersonatingVerifier),
            clientId: impersonatingVerifier.clientId
        )
    }

    func testShouldRejectASelfSignedLeafCertificateThatIsNotATrustAnchorAsUntrusted() async {
        let selfSignedVerifier = X509HashTestData.createSelfSignedVerifierCredential()

        await assertRequestObjectRejectedAsUntrusted(
            signedRequestObject(credential: selfSignedVerifier),
            clientId: selfSignedVerifier.clientId
        )
    }

    func testShouldRejectASelfSignedLeafCertificateEvenWhenItIsConfiguredAsATrustAnchor() async {
        let selfSignedVerifier = X509HashTestData.createSelfSignedVerifierCredential()
        walletConfig = makeWalletConfig(verifierTrustAnchors: [selfSignedVerifier.x5cEntry])

        await assertRequestObjectRejected(
            signedRequestObject(credential: selfSignedVerifier),
            expectedMessage: "Leaf certificate in x5c must not be self-signed",
            clientId: selfSignedVerifier.clientId
        )
    }

    func testShouldRejectALeafCertificateWhoseKeyUsageDoesNotAllowDigitalSignature() async {
        let keyEnciphermentVerifier = X509HashTestData.createVerifierCredential(keyUsage: KeyUsage(keyEncipherment: true))

        await assertRequestObjectRejected(
            signedRequestObject(credential: keyEnciphermentVerifier),
            expectedMessage: "Key usage of the leaf certificate in x5c does not allow digitalSignature",
            clientId: keyEnciphermentVerifier.clientId
        )
    }

    func testShouldRejectTheRequestWhenAnIntermediateX5cEntryIsNotACertificate() async {
        var header = X509HashTestData.requestObjectHeader(verifier)
        header["x5c"] = [verifier.x5cEntry, Data("not a certificate".utf8).base64EncodedString()]

        await assertRequestObjectRejected(
            signedRequestObject(header: header),
            expectedMessage: "x5c[1] is not a valid DER-encoded X.509 certificate"
        )
    }

    func testShouldRejectTheRequestWhenAnIntermediateX5cEntryIsNotStandardBase64() async {
        var header = X509HashTestData.requestObjectHeader(verifier)
        header["x5c"] = [verifier.x5cEntry, "-_not-base64"]

        await assertRequestObjectRejected(
            signedRequestObject(header: header),
            expectedMessage: "x5c[1] must be a base64-encoded DER X.509 certificate"
        )
    }

    func testShouldRejectTheRequestWhenTheClientIdInTheRequestObjectDiffersFromTheOneReceived() async {
        let otherVerifier = X509HashTestData.createVerifierCredential()
        let payload = X509HashTestData.requestObjectPayload(clientId: otherVerifier.clientId)

        await XCTAssertAsyncThrowsError(
            try await createHandler(requestByValue(signedRequestObject(payload: payload))).handle()
        ) { error in
            XCTAssertTrue(error is MismatchingClientIDInRequest, "\(error)")
        }
    }

    func testShouldRejectADraft23StyleRequestWithPresentationDefinition() async {
        var payload = X509HashTestData.requestObjectPayload(clientId: verifier.clientId)
        payload.removeValue(forKey: AuthorizationRequestFieldConstants.dcqlQuery)
        payload[AuthorizationRequestFieldConstants.presentationDefinition] = presentationDefinition

        await XCTAssertAsyncThrowsError(
            try await createHandler(requestByValue(signedRequestObject(payload: payload))).handle()
        ) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Spec version identification from request parameters failed",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testGetWalletMetadataShouldListX509HashAndTheSupportedRequestObjectSigningAlgorithms() throws {
        let walletMetadata = try createHandler(requestByValue()).getWalletMetadata(walletConfig: walletConfig)

        XCTAssertEqual(["x509_hash"], walletMetadata["client_id_prefixes_supported"] as? [String])
        XCTAssertEqual(["ES256", "EdDSA"], walletMetadata["request_object_signing_alg_values_supported"] as? [String])
    }

    func testGetWalletMetadataShouldListOnlyTheAlgorithmsX509HashVerifies() throws {
        walletConfig = makeWalletConfig(requestObjectSigningAlgValuesSupported: [.edDsa, .es256, .rs256, .es256k1])

        let walletMetadata = try createHandler(requestByValue()).getWalletMetadata(walletConfig: walletConfig)

        XCTAssertEqual(["EdDSA", "ES256"], walletMetadata["request_object_signing_alg_values_supported"] as? [String])
    }

    func testShouldAcceptATrustAnchorWrappedOverSeveralLines() async throws {
        let rootBase64 = X509HashTestData.rootCertificateAuthority.x5cEntry
        let wrappedRootBase64 = stride(from: 0, to: rootBase64.count, by: 64).map { offset -> String in
            let start = rootBase64.index(rootBase64.startIndex, offsetBy: offset)
            let end = rootBase64.index(start, offsetBy: 64, limitedBy: rootBase64.endIndex) ?? rootBase64.endIndex
            return String(rootBase64[start..<end])
        }.joined(separator: "\n")
        walletConfig = makeWalletConfig(verifierTrustAnchors: [wrappedRootBase64])

        let authorizationRequest = try await createHandler(requestByValue()).handle()

        XCTAssertEqual(verifier.clientId, authorizationRequest.clientId)
    }

    func testExtractPublicKeyShouldReturnThePublicKeyOfTheLeafCertificateInX5c() async throws {
        let publicKey = try await createHandler(requestByValue()).extractPublicKey(
            algorithm: "ES256",
            jwsHeader: X509HashTestData.requestObjectHeader(verifier)
        )

        guard case .secKey(let secKey) = publicKey else {
            return XCTFail("Expected an EC SecKey for ES256, got \(publicKey)")
        }
        let expectedKey = try XCTUnwrap(P256.Signing.PublicKey(verifier.certificate.publicKey))
        XCTAssertEqual(expectedKey.x963Representation, SecKeyCopyExternalRepresentation(secKey, nil) as Data?)
    }

    private func makeWalletConfig(
        clientIdPrefixesSupported: [ClientIdPrefix] = [.x509Hash],
        requestObjectSigningAlgValuesSupported: [SignatureAlgorithm]? = [.es256, .edDsa],
        verifierTrustAnchors: [String] = [X509HashTestData.rootCertificateAuthority.x5cEntry]
    ) -> WalletConfig {
        return WalletConfig(
            clientIdPrefixesSupported: clientIdPrefixesSupported,
            requestObjectSigningAlgValuesSupported: requestObjectSigningAlgValuesSupported,
            verifierTrustAnchors: verifierTrustAnchors
        )
    }

    private func createHandler(_ parameters: [String: Any]) -> X509HashPrefixAuthorizationRequestHandler {
        return X509HashPrefixAuthorizationRequestHandler(
            clientId: parameters[AuthorizationRequestFieldConstants.clientId] as! String,
            specVersion: .v1,
            authorizationRequestParameters: parameters,
            walletConfig: walletConfig,
            setResponseDispatchInfo: mockSetResponseDispatchInfo,
            walletNonce: walletNonce,
            networkManager: mockNetworkManager
        )
    }

    private func requestByValue(_ request: String? = nil, clientId: String? = nil) -> [String: Any] {
        return [
            AuthorizationRequestFieldConstants.clientId: clientId ?? verifier.clientId,
            AuthorizationRequestFieldConstants.request: request ?? signedRequestObject()
        ]
    }

    private func signedRequestObject(
        credential: X509VerifierCredential? = nil,
        clientId: String? = nil,
        alg: String = "ES256",
        header: [String: Any]? = nil,
        payload: [String: Any]? = nil,
        signingKey: VerifierSigningKey? = nil
    ) -> String {
        let credential = credential ?? verifier
        return X509HashTestData.signRequestObject(
            header: header ?? X509HashTestData.requestObjectHeader(credential, alg: alg),
            payload: payload ?? X509HashTestData.requestObjectPayload(clientId: clientId ?? credential.clientId),
            signingKey: signingKey ?? credential.signingKey
        )
    }

    private func assertRequestObjectRejected(
        _ request: String,
        expectedMessage: String,
        clientId: String? = nil,
        file: StaticString = #file,
        line: UInt = #line
    ) async {
        await XCTAssertAsyncThrowsError(try await createHandler(requestByValue(request, clientId: clientId)).handle()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Request URI response validation failed - \(expectedMessage)",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequestObject,
                                     file: file,
                                     line: line)
        }
    }

    private func assertRequestObjectRejectedAsUntrusted(_ request: String, clientId: String) async {
        await XCTAssertAsyncThrowsError(try await createHandler(requestByValue(request, clientId: clientId)).handle()) { error in
            let exception = error as? OpenID4VPException
            XCTAssertEqual(OpenID4VPErrorCodes.invalidRequestObject, exception?.errorCode)
            XCTAssertTrue(
                exception?.message.hasPrefix("Request URI response validation failed - x5c certificate chain is not trusted: ") == true,
                "\(error)"
            )
        }
    }
}

enum VerifierKeyType {
    case p256
    case ed25519
}

enum VerifierSigningKey {
    case p256(P256.Signing.PrivateKey)
    case ed25519(Curve25519.Signing.PrivateKey)
}

func derEncodedCertificate(_ certificate: Certificate) -> Data {
    var serializer = DER.Serializer()
    try! serializer.serialize(certificate)
    return Data(serializer.serializedBytes)
}

func secCertificateOf(_ certificate: Certificate) -> SecCertificate {
    return SecCertificateCreateWithData(nil, derEncodedCertificate(certificate) as CFData)!
}

func x5cEntryOf(_ certificate: Certificate) -> String {
    return derEncodedCertificate(certificate).base64EncodedString()
}

final class TestCertificateAuthority {
    let certificate: Certificate
    let privateKey: P256.Signing.PrivateKey
    let issuer: TestCertificateAuthority?

    init(certificate: Certificate, privateKey: P256.Signing.PrivateKey, issuer: TestCertificateAuthority? = nil) {
        self.certificate = certificate
        self.privateKey = privateKey
        self.issuer = issuer
    }

    var x5cEntry: String {
        return x5cEntryOf(certificate)
    }

    // x5c leaves out the root CA (HAIP 1.0)
    var intermediateCertificates: [Certificate] {
        guard let issuer = issuer else {
            return []
        }
        return [certificate] + issuer.intermediateCertificates
    }
}

struct X509VerifierCredential {
    let certificate: Certificate
    let signingKey: VerifierSigningKey
    let intermediateCertificates: [Certificate]

    var certificateHash: String {
        return Data(SHA256.hash(data: derEncodedCertificate(certificate))).toBase64UrlEncoded()
    }

    var clientId: String {
        return "\(ClientIdPrefix.x509Hash.rawValue):\(certificateHash)"
    }

    var x5cEntry: String {
        return x5cEntryOf(certificate)
    }

    var x5c: [String] {
        return ([certificate] + intermediateCertificates).map(x5cEntryOf)
    }
}

enum X509HashTestData {
    static let requestObjectType = "oauth-authz-req+jwt"
    static let dayInSeconds: TimeInterval = 24 * 60 * 60

    static let rootCertificateAuthority = createCertificateAuthority(commonName: "Demo Root CA")
    static let intermediateCertificateAuthority = createCertificateAuthority(
        commonName: "Demo Issuing CA",
        issuer: rootCertificateAuthority
    )

    static func createCertificateAuthority(
        commonName: String,
        organization: String = "Demo Trust Services",
        issuer: TestCertificateAuthority? = nil,
        notValidBefore: Date = Date() - X509HashTestData.dayInSeconds,
        notValidAfter: Date = Date() + 3650 * X509HashTestData.dayInSeconds
    ) -> TestCertificateAuthority {
        let privateKey = P256.Signing.PrivateKey()
        let subject = distinguishedName(organization: organization, commonName: commonName)
        let certificate = try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(privateKey.publicKey),
            notValidBefore: notValidBefore,
            notValidAfter: notValidAfter,
            issuer: issuer?.certificate.subject ?? subject,
            subject: subject,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try! Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
            },
            issuerPrivateKey: .init(issuer?.privateKey ?? privateKey)
        )
        return TestCertificateAuthority(certificate: certificate, privateKey: privateKey, issuer: issuer)
    }

    // keyUsage nil leaves the key usage extension out
    static func createVerifierCredential(
        keyType: VerifierKeyType = .p256,
        organization: String = "Demo Bank",
        commonName: String = "Demo Verifier",
        notValidBefore: Date = Date() - X509HashTestData.dayInSeconds,
        notValidAfter: Date = Date() + 365 * X509HashTestData.dayInSeconds,
        issuer: TestCertificateAuthority = X509HashTestData.rootCertificateAuthority,
        keyUsage: KeyUsage? = KeyUsage(digitalSignature: true)
    ) -> X509VerifierCredential {
        let (publicKey, signingKey) = generateVerifierKey(keyType)
        let certificate = createLeafCertificate(
            publicKey: publicKey,
            subject: distinguishedName(organization: organization, commonName: commonName),
            issuerName: issuer.certificate.subject,
            issuerPrivateKey: issuer.privateKey,
            notValidBefore: notValidBefore,
            notValidAfter: notValidAfter,
            keyUsage: keyUsage
        )
        return X509VerifierCredential(
            certificate: certificate,
            signingKey: signingKey,
            intermediateCertificates: issuer.intermediateCertificates
        )
    }

    static func createSelfSignedVerifierCredential() -> X509VerifierCredential {
        let privateKey = P256.Signing.PrivateKey()
        let subject = distinguishedName(organization: "Demo Bank", commonName: "Demo Verifier")
        let certificate = createLeafCertificate(
            publicKey: .init(privateKey.publicKey),
            subject: subject,
            issuerName: subject,
            issuerPrivateKey: privateKey,
            notValidBefore: Date() - dayInSeconds,
            notValidAfter: Date() + 365 * dayInSeconds,
            keyUsage: KeyUsage(digitalSignature: true)
        )
        return X509VerifierCredential(certificate: certificate, signingKey: .p256(privateKey), intermediateCertificates: [])
    }

    static func requestObjectHeader(_ credential: X509VerifierCredential, alg: String = "ES256") -> [String: Any] {
        return [
            "typ": requestObjectType,
            "alg": alg,
            "x5c": credential.x5c
        ]
    }

    static func requestObjectPayload(clientId: String, walletNonce: String? = nil) -> [String: Any] {
        var payload: [String: Any] = [
            "client_id": clientId,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "response_uri": "https://mock-verifier.com/response-uri",
            "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
            "state": "+mRQe1d6pBoJqF6Ab28klg==",
            "dcql_query": [
                "credentials": [
                    ["id": "identity_credential", "format": "ldp_vc", "meta": [String: Any]()]
                ]
            ]
        ]
        if let walletNonce = walletNonce {
            payload["wallet_nonce"] = walletNonce
        }
        return payload
    }

    // Signs by key type, whatever alg the header declares
    static func signRequestObject(header: [String: Any], payload: [String: Any], signingKey: VerifierSigningKey) -> String {
        let encodedHeader = try! JSONSerialization.data(withJSONObject: header).toBase64UrlEncoded()
        let encodedPayload = try! JSONSerialization.data(withJSONObject: payload).toBase64UrlEncoded()
        let signingInput = Data("\(encodedHeader).\(encodedPayload)".utf8)
        let signature: Data
        switch signingKey {
        case .p256(let privateKey):
            // JWS carries ECDSA signatures as R || S
            signature = try! privateKey.signature(for: signingInput).rawRepresentation
        case .ed25519(let privateKey):
            signature = try! privateKey.signature(for: signingInput)
        }
        return "\(encodedHeader).\(encodedPayload).\(signature.toBase64UrlEncoded())"
    }

    private static func generateVerifierKey(_ keyType: VerifierKeyType) -> (Certificate.PublicKey, VerifierSigningKey) {
        switch keyType {
        case .p256:
            let privateKey = P256.Signing.PrivateKey()
            return (Certificate.PublicKey(privateKey.publicKey), .p256(privateKey))
        case .ed25519:
            let privateKey = Curve25519.Signing.PrivateKey()
            return (Certificate.PublicKey(privateKey.publicKey), .ed25519(privateKey))
        }
    }

    private static func createLeafCertificate(
        publicKey: Certificate.PublicKey,
        subject: DistinguishedName,
        issuerName: DistinguishedName,
        issuerPrivateKey: P256.Signing.PrivateKey,
        notValidBefore: Date,
        notValidAfter: Date,
        keyUsage: KeyUsage?
    ) -> Certificate {
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: publicKey,
            notValidBefore: notValidBefore,
            notValidAfter: notValidAfter,
            issuer: issuerName,
            subject: subject,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try! Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                if let keyUsage = keyUsage {
                    Critical(keyUsage)
                }
            },
            issuerPrivateKey: .init(issuerPrivateKey)
        )
    }

    private static func distinguishedName(organization: String, commonName: String) -> DistinguishedName {
        return try! DistinguishedName {
            CountryName("IN")
            OrganizationName(organization)
            CommonName(commonName)
        }
    }
}
