import Foundation
import Security
import SwiftASN1
import X509

/// Exactly one DER-encoded certificate; swift-asn1 rejects trailing data.
func parseX509Certificate(_ der: Data) throws -> Certificate {
    return try Certificate(derEncoded: Array(der))
}

/// Standard base64, skipping whitespace; isWhitespace also covers "\r\n", a single Character in Swift.
func decodeBase64IgnoringWhitespace(_ base64: String) -> Data? {
    return Data(base64Encoded: base64.filter { !$0.isWhitespace })
}

struct CertificationPathValidationFailure: LocalizedError {
    let reason: String

    var errorDescription: String? {
        return reason
    }
}

/// Validates the chain (DER, leaf first) to one of the trust anchors with SecTrust, as the EUDI iOS wallet does.
/// Revocation is not checked and missing certificates are not fetched.
func validateCertificationPath(_ certificateChain: [Data], trustAnchors: [SecCertificate]) throws {
    let certificates = certificateChain.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
    guard !certificates.isEmpty, certificates.count == certificateChain.count else {
        throw CertificationPathValidationFailure(reason: "A certificate in the chain could not be read")
    }
    var secTrust: SecTrust?
    let status = SecTrustCreateWithCertificates(certificates as CFArray, SecPolicyCreateBasicX509(), &secTrust)
    guard status == errSecSuccess, let trust = secTrust,
          SecTrustSetAnchorCertificates(trust, trustAnchors as CFArray) == errSecSuccess,
          SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
          SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess else {
        throw CertificationPathValidationFailure(reason: "Trust evaluation could not be set up")
    }
    var error: CFError?
    guard SecTrustEvaluateWithError(trust, &error) else {
        throw CertificationPathValidationFailure(
            reason: (error as Error?)?.localizedDescription ?? "The certificate chain is not trusted"
        )
    }
}

extension Certificate {
    var isSelfSigned: Bool {
        return issuer == subject && publicKey.isValidSignature(signature, for: self)
    }
}
