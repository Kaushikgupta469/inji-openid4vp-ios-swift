import Foundation
import XCTest
@testable import OpenID4VP

final class ConstantsTests: XCTestCase {

    func testRequestUriMethodMapsGetToHttpGet() {
        XCTAssertEqual(RequestUriMethod.get.toHttpMethod(), HttpMethod.get)
    }

    func testRequestUriMethodMapsPostToHttpPost() {
        XCTAssertEqual(RequestUriMethod.post.toHttpMethod(), HttpMethod.post)
    }

    func testRequestUriMethodDecodesFromRawValue() {
        XCTAssertEqual(RequestUriMethod(rawValue: "get"), .get)
        XCTAssertEqual(RequestUriMethod(rawValue: "post"), .post)
        XCTAssertNil(RequestUriMethod(rawValue: "patch"))
    }

    func testProofTypeFromValueResolvesSupportedTypes() {
        XCTAssertEqual(ProofType.fromValue("Ed25519Signature2020"), .ed25519Signature2020)
        XCTAssertEqual(ProofType.fromValue("JsonWebSignature2020"), .jsonWebSignature2020)
    }

    func testProofTypeFromValueReturnsNilForUnknownType() {
        XCTAssertNil(ProofType.fromValue("RsaSignature2018"))
    }

    func testProofTypeFromValueIsCaseSensitive() {
        XCTAssertNil(ProofType.fromValue("ed25519signature2020"))
    }

    func testProofPurposeUsesAuthenticationRawValue() {
        XCTAssertEqual(ProofPurpose.vpProofPurpose.rawValue, "authentication")
    }

    func testLimitDisclosureDecodesPreferred() {
        XCTAssertEqual(LimitDisclosure(rawValue: "preferred"), .preferred)
        XCTAssertNil(LimitDisclosure(rawValue: "required"))
    }

    func testDidMethodRawValues() {
        XCTAssertEqual(DIDMethod.web.rawValue, "web")
        XCTAssertEqual(DIDMethod.key.rawValue, "key")
        XCTAssertEqual(DIDMethod.jwk.rawValue, "jwk")
    }

    func testDidMethodDecodesFromRawValue() {
        XCTAssertEqual(DIDMethod(rawValue: "key"), .key)
        XCTAssertNil(DIDMethod(rawValue: "ion"))
    }

    func testPublicKeyVerificationMaterialCoversAllSupportedMaterials() {
        XCTAssertEqual(
            Set(PublicKeyVerificationMaterial.allCases.map { $0.rawValue }),
            ["publicKeyJwk", "publicKeyHex", "publicKeyMultibase", "publicKeyPem"]
        )
    }

    func testPublicKeyVerificationMaterialDecodesFromRawValue() {
        XCTAssertEqual(PublicKeyVerificationMaterial(rawValue: "publicKeyJwk"), .jwk)
        XCTAssertNil(PublicKeyVerificationMaterial(rawValue: "publicKeyUnknown"))
    }

    func testJwsAlgorithmSupportedListContainsExpectedAlgorithms() {
        XCTAssertEqual(
            JWSAlgorithm.supported,
            ["EdDSA", "RS256", "ES256", "ES384", "ES256K"]
        )
    }

    func testJwsAlgorithmSupportedListExcludesNone() {
        XCTAssertFalse(JWSAlgorithm.supported.contains("none"))
    }

    func testJwsAlgorithmNormalizedReturnsCanonicalCasing() {
        XCTAssertEqual(JWSAlgorithm.normalized("eddsa"), "EdDSA")
        XCTAssertEqual(JWSAlgorithm.normalized("es256"), "ES256")
        XCTAssertEqual(JWSAlgorithm.normalized("RS256"), "RS256")
    }

    func testJwsAlgorithmNormalizedAcceptsExactMatch() {
        XCTAssertEqual(JWSAlgorithm.normalized("ES384"), "ES384")
        XCTAssertEqual(JWSAlgorithm.normalized("ES256K"), "ES256K")
    }

    func testJwsAlgorithmNormalizedRejectsUnsupportedAlgorithm() {
        XCTAssertNil(JWSAlgorithm.normalized("none"))
        XCTAssertNil(JWSAlgorithm.normalized("HS256"))
        XCTAssertNil(JWSAlgorithm.normalized(""))
    }

    func testVerifierMetadataConstantsExposeSpecFieldNames() {
        XCTAssertEqual(VerifierMetadataConstants.clientName, "client_name")
        XCTAssertEqual(VerifierMetadataConstants.logoUri, "logo_uri")
        XCTAssertEqual(VerifierMetadataConstants.vpFormats, "vp_formats")
    }

    func testVerifierMetadataConstantsDistinguishSpecVersions() {
        XCTAssertEqual(
            VerifierMetadataConstants.encryptedResponseEncValuesSupported,
            "encrypted_response_enc_values_supported"
        )
        XCTAssertEqual(
            VerifierMetadataConstants.authorizationEncryptedResponseAlg,
            "authorization_encrypted_response_alg"
        )
        XCTAssertEqual(
            VerifierMetadataConstants.authorizationEncryptedResponseEnc,
            "authorization_encrypted_response_enc"
        )
    }

    func testDeviceAuthenticationRetainsSignatureAndAlgorithm() {
        let signature = Data([0x01, 0x02, 0x03])
        let deviceAuthentication = DeviceAuthentication(signature: signature, algorithm: "ES256")

        XCTAssertEqual(deviceAuthentication.signature, signature)
        XCTAssertEqual(deviceAuthentication.algorithm, "ES256")
    }
}
