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
    // The trust anchor must be a CA that is allowed to sign certificates
    if let trustAnchor = evaluatedCertificateChain(of: trust).last,
       SecCertificateCopyData(trustAnchor) as Data != certificateChain[0] {
        try validateTrustAnchorCanSignCertificates(trustAnchor)
    }
}

private func evaluatedCertificateChain(of trust: SecTrust) -> [SecCertificate] {
    if #available(iOS 15.0, macOS 12.0, *) {
        return SecTrustCopyCertificateChain(trust) as? [SecCertificate] ?? []
    }
    return (0..<SecTrustGetCertificateCount(trust)).compactMap { SecTrustGetCertificateAtIndex(trust, $0) }
}

private func validateTrustAnchorCanSignCertificates(_ trustAnchor: SecCertificate) throws {
    guard let certificate = try? Certificate(derEncoded: Array(SecCertificateCopyData(trustAnchor) as Data)) else {
        throw CertificationPathValidationFailure(reason: "The trust anchor could not be read")
    }
    guard case .some(.isCertificateAuthority) = try? certificate.extensions.basicConstraints else {
        throw CertificationPathValidationFailure(reason: "Trust anchor \(certificate.subject) is not a CA certificate")
    }
    if let keyUsage = try? certificate.extensions.keyUsage, !keyUsage.keyCertSign {
        throw CertificationPathValidationFailure(
            reason: "Key usage of trust anchor \(certificate.subject) does not allow keyCertSign"
        )
    }
}
