import Foundation
import XCTest
import X509
@testable import OpenID4VP

class X509CertificateUtilsTests: XCTestCase {
    let verifier = X509HashTestData.createVerifierCredential()

    func testParseX509CertificateShouldParseADerEncodedCertificate() throws {
        let certificate = try parseX509Certificate(derEncodedCertificate(verifier.certificate))

        XCTAssertEqual(verifier.certificate, certificate)
    }

    func testParseX509CertificateShouldRejectDataThatIsNotExactlyOneDerEncodedCertificate() {
        let der = derEncodedCertificate(verifier.certificate)
        let pem = "-----BEGIN CERTIFICATE-----\n\(verifier.x5cEntry)\n-----END CERTIFICATE-----\n"
        let invalidInputs = [Data("not a certificate".utf8), der + Data([0x00]), Data(pem.utf8)]

        for input in invalidInputs {
            XCTAssertThrowsError(try parseX509Certificate(input))
        }
    }

    func testValidateCertificationPathShouldAcceptAChainThroughAnIntermediateCAToTheRootCA() throws {
        let intermediateIssuedVerifier = X509HashTestData.createVerifierCredential(
            issuer: X509HashTestData.intermediateCertificateAuthority
        )

        try validateCertificationPath(
            ([intermediateIssuedVerifier.certificate] + intermediateIssuedVerifier.intermediateCertificates).map(derEncodedCertificate),
            trustAnchors: [secCertificateOf(X509HashTestData.rootCertificateAuthority.certificate)]
        )
    }

    func testValidateCertificationPathShouldRejectAChainThatDoesNotLeadToATrustAnchor() {
        let otherCertificateAuthority = X509HashTestData.createCertificateAuthority(
            commonName: "Other Root CA",
            organization: "Other Trust Services"
        )

        XCTAssertThrowsError(
            try validateCertificationPath(
                [derEncodedCertificate(verifier.certificate)],
                trustAnchors: [secCertificateOf(otherCertificateAuthority.certificate)]
            )
        ) { error in
            XCTAssertTrue(error is CertificationPathValidationFailure, "\(error)")
        }
    }

    func testDecodeBase64IgnoringWhitespaceShouldSkipLineBreaksButRejectBase64UrlCharacters() {
        XCTAssertEqual(Data("hello world".utf8), decodeBase64IgnoringWhitespace("aGVsbG8g\nd29y\r\nbGQ="))
        XCTAssertNil(decodeBase64IgnoringWhitespace("-_8A"))
    }

    func testIsSelfSignedShouldBeTrueOnlyForACertificateThatVerifiesWithItsOwnKey() {
        XCTAssertTrue(X509HashTestData.rootCertificateAuthority.certificate.isSelfSigned)
        XCTAssertTrue(X509HashTestData.createSelfSignedVerifierCredential().certificate.isSelfSigned)
        XCTAssertFalse(X509HashTestData.intermediateCertificateAuthority.certificate.isSelfSigned)
        XCTAssertFalse(verifier.certificate.isSelfSigned)
    }
}
