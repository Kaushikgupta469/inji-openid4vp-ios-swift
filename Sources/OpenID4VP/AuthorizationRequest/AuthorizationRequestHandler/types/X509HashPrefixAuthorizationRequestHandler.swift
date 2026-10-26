import Foundation
import CryptoKit
import Security
import X509

private let x5cHeaderParameter = "x5c"

// base64url SHA-256 hash without padding; \z because $ also matches before a trailing newline
private let certificateHashPattern = "^[A-Za-z0-9_-]{43}\\z"

/// x509_hash Client Identifier Prefix, OpenID4VP 1.0 section 5.9.3
class X509HashPrefixAuthorizationRequestHandler: ClientIdPrefixBasedAuthorizationRequestHandler {
    override init(clientId: String,
                  specVersion: SpecVersion,
                  authorizationRequestParameters: [String: Any],
                  walletConfig: WalletConfig,
                  setResponseDispatchInfo: @escaping (ResponseDispatchInfo) -> Void,
                  walletNonce: String,
                  networkManager: NetworkManaging) {
        super.init(clientId: clientId,
                   specVersion: specVersion,
                   authorizationRequestParameters: authorizationRequestParameters,
                   walletConfig: walletConfig,
                   setResponseDispatchInfo: setResponseDispatchInfo,
                   walletNonce: walletNonce,
                   networkManager: networkManager)
        delegate = self
        super.className = String(describing: X509HashPrefixAuthorizationRequestHandler.self)
    }

    private var certificateHash: String {
        return extractClientIdPartOnly(clientId)
    }

    func clientIdPrefix() -> String {
        return ClientIdPrefix.x509Hash.rawValue
    }

    override func validateClientId() throws {
        guard walletConfig.clientIdPrefixesSupported.contains(.x509Hash) else {
            throw InvalidData(
                message: "client_id_prefix \(ClientIdPrefix.x509Hash.rawValue) is not supported by wallet",
                className: className
            )
        }
        guard certificateHash.range(of: certificateHashPattern, options: .regularExpression) != nil else {
            throw InvalidData(
                message: "client_id must be \(ClientIdPrefix.x509Hash.rawValue):<base64url-encoded SHA-256 hash of the leaf certificate>",
                className: className
            )
        }
    }

    func isSignedRequestSupported() -> Bool {
        return true
    }

    func isUnsignedRequestSupported() -> Bool {
        return false
    }

    func confirmSpecVersionIdentifiedFromRequest() -> Bool {
        return specVersion == .v1
    }

    func extractPublicKey(algorithm: String, jwsHeader: [String: Any]) async throws -> PublicKeyType {
        let certificateChainBytes = try extractCertificateChainBytes(jwsHeader)

        guard Data(SHA256.hash(data: certificateChainBytes[0])).toBase64UrlEncoded() == certificateHash else {
            throw invalidRequestObject("client_id does not match the SHA-256 hash of the leaf certificate in x5c")
        }

        let certificateChain = try certificateChainBytes.enumerated().map { (index, certificateBytes) -> Certificate in
            do {
                return try parseX509Certificate(certificateBytes)
            } catch {
                throw invalidRequestObject("x5c[\(index)] is not a valid DER-encoded X.509 certificate")
            }
        }
        let leafCertificate = certificateChain[0]

        let leafPublicKey = try publicKey(of: leafCertificate, matching: algorithm)
        try validateValidityPeriod(leafCertificate)
        try validateKeyUsage(leafCertificate)
        try validateTrustChain(leafCertificate: leafCertificate, certificateChainBytes: certificateChainBytes)

        return leafPublicKey
    }

    func getWalletMetadata(walletConfig: WalletConfig) throws -> [String: Any] {
        try validateRequestObjectSigningAlgSupported(walletConfig, className: className)
        let signingAlgorithms = (walletConfig.requestObjectSigningAlgValuesSupported ?? [])
            .filter { supportedSignatureAlgorithms().contains($0) }
            .map { $0.rawValue }
        guard !signingAlgorithms.isEmpty else {
            throw InvalidData(
                message: "request_object_signing_alg_values_supported is not present in wallet metadata.",
                className: className
            )
        }
        var walletMetadata = try walletConfig.toWalletMetadata(specVersion: specVersion)
        walletMetadata[WalletMetadataConstants.requestObjectSigningAlgValuesSupported] = signingAlgorithms
        return walletMetadata
    }

    private func extractCertificateChainBytes(_ jwsHeader: [String: Any]) throws -> [Data] {
        guard let certificateChain = jwsHeader[x5cHeaderParameter] as? [Any], !certificateChain.isEmpty else {
            throw invalidRequestObject("x5c certificate chain is missing in the JWS header")
        }
        // x5c entries are standard base64, not base64url
        return try certificateChain.enumerated().map { (index, certificate) -> Data in
            guard let certificate = certificate as? String, !certificate.isEmpty,
                  let certificateBytes = Data(base64Encoded: certificate) else {
                throw invalidRequestObject("x5c[\(index)] must be a base64-encoded DER X.509 certificate")
            }
            return certificateBytes
        }
    }

    private func publicKey(of certificate: Certificate, matching algorithm: String) throws -> PublicKeyType {
        switch algorithm {
        case SignatureAlgorithm.es256.rawValue:
            if let p256PublicKey = P256.Signing.PublicKey(certificate.publicKey),
               let secKey = createSecKey(from: p256PublicKey.x963Representation) {
                return .secKey(secKey)
            }
        case SignatureAlgorithm.edDsa.rawValue:
            if let ed25519PublicKey = Curve25519.Signing.PublicKey(certificate.publicKey) {
                return .ed25519(ed25519PublicKey)
            }
        default:
            break
        }
        throw invalidRequestObject("Signing algorithm \(algorithm) does not match the leaf certificate key")
    }

    private func validateValidityPeriod(_ certificate: Certificate) throws {
        let now = Date()
        if now > certificate.notValidAfter {
            throw invalidRequestObject("Leaf certificate in x5c has expired")
        }
        if now < certificate.notValidBefore {
            throw invalidRequestObject("Leaf certificate in x5c is not yet valid")
        }
    }

    private func validateKeyUsage(_ certificate: Certificate) throws {
        let keyUsage: KeyUsage?
        do {
            keyUsage = try certificate.extensions.keyUsage
        } catch {
            throw invalidRequestObject("Key usage of the leaf certificate in x5c could not be read")
        }
        if let keyUsage = keyUsage, !keyUsage.digitalSignature {
            throw invalidRequestObject("Key usage of the leaf certificate in x5c does not allow digitalSignature")
        }
    }

    // OpenID4VP 1.0 section 5.9.3: the Wallet MUST validate the trust chain of the leaf certificate
    private func validateTrustChain(leafCertificate: Certificate, certificateChainBytes: [Data]) throws {
        let trustAnchors = try parseTrustAnchors()
        if trustAnchors.isEmpty {
            throw invalidRequestObject("No trust anchors are configured to validate the x5c certificate chain")
        }
        do {
            try validateCertificationPath(certificateChainBytes, trustAnchors: trustAnchors)
        } catch {
            throw invalidRequestObject("x5c certificate chain is not trusted: \(error.localizedDescription)")
        }
        // HAIP 1.0: the leaf must not be self-signed. Checked after the chain is trusted, so an untrusted key
        // is never used to verify a signature
        if leafCertificate.isSelfSigned {
            throw invalidRequestObject("Leaf certificate in x5c must not be self-signed")
        }
    }

    private func parseTrustAnchors() throws -> [SecCertificate] {
        return try walletConfig.verifierTrustAnchors.enumerated().map { (index, trustAnchor) -> SecCertificate in
            guard let trustAnchorBytes = decodeBase64IgnoringWhitespace(trustAnchor),
                  let certificate = SecCertificateCreateWithData(nil, trustAnchorBytes as CFData) else {
                throw invalidRequestObject(
                    "verifierTrustAnchors[\(index)] in the wallet configuration is not a base64-encoded DER X.509 certificate"
                )
            }
            return certificate
        }
    }

    private func invalidRequestObject(_ message: String) -> InvalidData {
        return InvalidData(message: message, className: className, code: OpenID4VPErrorCodes.invalidRequestObject)
    }
}
