import XCTest
@testable import OpenID4VP

private struct SampleCause: Error {}

final class OpenId4VPExceptionsTests: XCTestCase {

    private let className = "TestClass"

    func testBaseExceptionExposesProvidedValues() {
        let exception = OpenID4VPException(
            errorCode: "custom_code",
            message: "something went wrong",
            className: className
        )

        XCTAssertEqual(exception.errorCode, "custom_code")
        XCTAssertEqual(exception.message, "something went wrong")
        XCTAssertEqual(exception.className, className)
        XCTAssertNil(exception.cause)
        XCTAssertTrue(exception.notifyVerifier)
        XCTAssertNil(exception.verifierResponse)
    }

    func testBaseExceptionRetainsCause() {
        let cause = SampleCause()
        let exception = OpenID4VPException(
            errorCode: "custom_code",
            message: "wrapped",
            cause: cause,
            className: className
        )

        XCTAssertTrue(exception.cause is SampleCause)
    }

    func testBaseExceptionHonoursNotifyVerifierFalse() {
        let exception = OpenID4VPException(
            errorCode: "custom_code",
            message: "quiet",
            className: className,
            notifyVerifier: false
        )

        XCTAssertFalse(exception.notifyVerifier)
    }

    func testDescriptionCombinesErrorCodeAndMessage() {
        let exception = OpenID4VPException(
            errorCode: "invalid_request",
            message: "bad input",
            className: className
        )

        XCTAssertEqual(exception.description, "invalid_request : bad input")
    }

    func testErrorDescriptionReturnsMessage() {
        let exception = OpenID4VPException(
            errorCode: "invalid_request",
            message: "bad input",
            className: className
        )

        XCTAssertEqual(exception.errorDescription, "bad input")
    }

    func testToErrorResponseMapsCodeAndDescription() {
        let exception = OpenID4VPException(
            errorCode: "invalid_client",
            message: "unknown verifier",
            className: className
        )

        XCTAssertEqual(
            exception.toErrorResponse(),
            ["error": "invalid_client", "error_description": "unknown verifier"]
        )
    }

    func testToAuthorizationErrorResponseCarriesState() {
        let exception = OpenID4VPException(
            errorCode: "invalid_request",
            message: "bad input",
            className: className
        )

        let response = exception.toAuthorizationErrorResponse(state: "state-1")

        XCTAssertEqual(response.error, "invalid_request")
        XCTAssertEqual(response.errorDescription, "bad input")
        XCTAssertEqual(response.state, "state-1")
    }

    func testToAuthorizationErrorResponseAllowsNilState() {
        let exception = OpenID4VPException(
            errorCode: "invalid_request",
            message: "bad input",
            className: className
        )

        let response = exception.toAuthorizationErrorResponse(state: nil)

        XCTAssertNil(response.state)
    }

    func testSetVerifierResponseStoresResponse() {
        let exception = OpenID4VPException(
            errorCode: "invalid_request",
            message: "bad input",
            className: className
        )
        let verifierResponse = VerifierResponse(statusCode: 200, headers: [:])

        exception.setVerifierResponse(verifierResponse)

        XCTAssertEqual(exception.verifierResponse?.statusCode, 200)
    }

    func testGetLogTagIncludesClassNameAndTraceabilityId() {
        OpenID4VPException.setTraceabilityId(className: className, traceabilityId: "trace-123")

        let logTag = OpenID4VPException.getLogTag("SomeClass")

        XCTAssertTrue(logTag.contains("INJI-OpenID4VP"))
        XCTAssertTrue(logTag.contains("SomeClass"))
        XCTAssertTrue(logTag.contains("trace-123"))
    }

    func testStaticLoggingHelpersDoNotCrash() {
        OpenID4VPException.error("tag", SampleCause())
        OpenID4VPException.warn("careful", className: className)
        OpenID4VPException.error(SampleCause(), className: className)
    }

    func testInvalidQueryParamsUsesInvalidRequest() {
        let exception = InvalidQueryParams(message: "missing param", className: className)

        XCTAssertEqual(exception.errorCode, OpenID4VPErrorCodes.invalidRequest)
        XCTAssertEqual(exception.message, "missing param")
    }

    func testInvalidVerifierUsesInvalidClient() {
        let exception = InvalidVerifier(message: "unknown verifier", className: className)

        XCTAssertEqual(exception.errorCode, OpenID4VPErrorCodes.invalidClient)
        XCTAssertEqual(exception.message, "unknown verifier")
    }

    func testInvalidInputPatternJoinsPathComponents() {
        let exception = InvalidInputPattern(fieldPath: ["a", "b", "c"], className: className)

        XCTAssertEqual(
            exception.message,
            "Invalid Input Pattern: a->b->c pattern is not matching with OpenId4VP specification"
        )
        XCTAssertEqual(exception.errorCode, OpenID4VPErrorCodes.invalidRequest)
    }

    func testInvalidInputPatternInterpolatesNonArrayPath() {
        let exception = InvalidInputPattern(fieldPath: "client_id", className: className)

        XCTAssertEqual(
            exception.message,
            "Invalid Input Pattern: client_id pattern is not matching with OpenId4VP specification"
        )
    }

    func testJsonEncodingFailedIncludesFieldAndError() {
        let exception = JsonEncodingFailed(
            fieldPath: "vp_token",
            errorMessage: "bad json",
            className: className
        )

        XCTAssertEqual(
            exception.message,
            "Json encoding failed for vp_token due to this error: bad json"
        )
        XCTAssertEqual(exception.errorCode, OpenID4VPErrorCodes.invalidRequest)
    }

    func testJsonEncodingFailedRendersNilFieldAsEmpty() {
        let exception = JsonEncodingFailed(errorMessage: "bad json", className: className)

        XCTAssertEqual(exception.message, "Json encoding failed for  due to this error: bad json")
    }

    func testEncodingFailedUsesProvidedErrorCode() {
        let exception = EncodingFailed(
            fieldPath: "nonce",
            errorMessage: "utf8 failure",
            errorCode: "server_error",
            className: className
        )

        XCTAssertEqual(exception.errorCode, "server_error")
        XCTAssertEqual(
            exception.message,
            "Encoding failed for nonce due to this error: utf8 failure"
        )
    }

    func testDeserializationFailureIncludesFieldAndError() {
        let exception = DeserializationFailure(
            fieldPath: "presentation_definition",
            errorMessage: "unexpected token",
            className: className
        )

        XCTAssertEqual(
            exception.message,
            "Deserializing for presentation_definition failed due to this error: unexpected token"
        )
    }

    func testInvalidLimitDisclosureHasFixedMessage() {
        let exception = InvalidLimitDisclosure(className: className)

        XCTAssertEqual(
            exception.message,
            "Invalid Input: constraints->limit_disclosure value should be preferred"
        )
        XCTAssertEqual(exception.errorCode, OpenID4VPErrorCodes.invalidRequest)
    }

    func testInvalidDataDefaultsToInvalidRequest() {
        let exception = InvalidData(message: "bad data", className: className)

        XCTAssertEqual(exception.errorCode, OpenID4VPErrorCodes.invalidRequest)
        XCTAssertEqual(exception.message, "bad data")
    }

    func testInvalidDataHonoursExplicitCode() {
        let exception = InvalidData(message: "bad data", className: className, code: "access_denied")

        XCTAssertEqual(exception.errorCode, "access_denied")
    }

    func testMissingInputFormatsStringField() {
        let exception = MissingInput(fieldPath: "client_id", className: className)

        XCTAssertEqual(exception.message, "Missing Input: client_id param is required")
        XCTAssertEqual(exception.errorCode, OpenID4VPErrorCodes.invalidRequest)
    }

    func testMissingInputJoinsArrayField() {
        let exception = MissingInput(fieldPath: ["a", "b"], className: className)

        XCTAssertEqual(exception.message, "Missing Input: a->b param is required")
    }

    func testMissingInputFallsBackToMessageForEmptyStringField() {
        let exception = MissingInput(
            fieldPath: "",
            message: "fallback message",
            className: className
        )

        XCTAssertEqual(exception.message, "fallback message")
    }

    func testMissingInputFallsBackToMessageForEmptyArrayField() {
        let exception = MissingInput(
            fieldPath: [String](),
            message: "fallback message",
            className: className
        )

        XCTAssertEqual(exception.message, "fallback message")
    }

    func testMissingInputHonoursNotifyVerifierFalse() {
        let exception = MissingInput(
            fieldPath: "client_id",
            className: className,
            notifyVerifier: false
        )

        XCTAssertFalse(exception.notifyVerifier)
    }

    func testInvalidInputReportsEmptyValue() {
        let exception = InvalidInput(fieldPath: "client_id", value: "", className: className)

        XCTAssertEqual(exception.message, "Invalid Input: client_id value cannot be empty or null")
    }

    func testInvalidInputTreatsWhitespaceValueAsEmpty() {
        let exception = InvalidInput(fieldPath: "client_id", value: "   ", className: className)

        XCTAssertEqual(exception.message, "Invalid Input: client_id value cannot be empty or null")
    }

    func testInvalidInputReportsNilValue() {
        let exception = InvalidInput(fieldPath: "client_id", value: nil, className: className)

        XCTAssertEqual(exception.message, "Invalid Input: client_id value cannot be empty or null")
    }

    func testInvalidInputReportsBooleanValue() {
        let exception = InvalidInput(fieldPath: "flag", value: true, className: className)

        XCTAssertEqual(exception.message, "Invalid Input: flag value must be either true or false")
    }

    func testInvalidInputReportsGenericInvalidValue() {
        let exception = InvalidInput(fieldPath: "count", value: 42, className: className)

        XCTAssertEqual(exception.message, "Invalid Input: count value is invalid")
    }

    func testInvalidInputJoinsArrayFieldPath() {
        let exception = InvalidInput(fieldPath: ["a", "b"], value: 42, className: className)

        XCTAssertEqual(exception.message, "Invalid Input: a->b value is invalid")
    }

    func testInvalidInputHonoursNotifyVerifierFalse() {
        let exception = InvalidInput(
            fieldPath: "client_id",
            value: nil,
            className: className,
            notifyVerifier: false
        )

        XCTAssertFalse(exception.notifyVerifier)
    }

    func testUnsupportedPublicKeyTypeListsSupportedTypes() {
        let exception = UnsupportedPublicKeyType(className: className)

        XCTAssertEqual(
            exception.message,
            "Unsupported Public Key type. Supported: publicKeyMultibase, publicKeyJwk, publicKeyHex, publicKeyPem"
        )
    }

    func testKidExtractionFailedHasFixedMessage() {
        let exception = KidExtractionFailed(className: className)

        XCTAssertEqual(exception.message, "Kid extraction from did document failed")
    }

    func testPublicKeyResolutionFailedDefaultsToInvalidRequest() {
        let exception = PublicKeyResolutionFailed(message: "no key", className: className)

        XCTAssertEqual(exception.errorCode, OpenID4VPErrorCodes.invalidRequest)
        XCTAssertEqual(exception.message, "no key")
    }

    func testPublicKeyResolutionFailedHonoursExplicitCode() {
        let exception = PublicKeyResolutionFailed(
            message: "no key",
            className: className,
            code: "server_error"
        )

        XCTAssertEqual(exception.errorCode, "server_error")
    }

    func testInvalidSignatureHasFixedMessage() {
        let exception = InvalidSignature(className: className)

        XCTAssertEqual(exception.message, "JWS proof verification failed")
    }

    func testVerificationFailurePassesMessageThrough() {
        let exception = VerificationFailure(message: "not verified", className: className)

        XCTAssertEqual(exception.message, "not verified")
    }

    func testJsonDecodingFailedPassesMessageThrough() {
        let exception = JsonDecodingFailed(message: "bad payload", className: className)

        XCTAssertEqual(exception.message, "bad payload")
    }

    func testJweEncryptionFailurePassesMessageThrough() {
        let exception = JweEncryptionFailure(message: "encryption failed", className: className)

        XCTAssertEqual(exception.message, "encryption failed")
    }

    func testUnsupportedEncryptionAlgorithmHasFixedMessage() {
        let exception = UnsupportedEncryptionAlgorithm(className: className)

        XCTAssertEqual(exception.message, "Required Encryption algorithm is not supported")
    }

    func testUnsupportedDidUrlHasFixedMessage() {
        let exception = UnsupportedDidUrl(className: className)

        XCTAssertEqual(exception.message, "Given did url is not supported")
    }

    func testDidResolutionFailedPassesMessageThrough() {
        let exception = DidResolutionFailed(message: "unreachable", className: className)

        XCTAssertEqual(exception.message, "unreachable")
    }

    func testPayloadConversionFailedHasFixedMessage() {
        let exception = PayloadConversionFailed(className: className)

        XCTAssertEqual(exception.message, "Failed to convert payload to Data")
    }

    func testInvalidResponseModePassesMessageThrough() {
        let exception = InvalidResponseMode(message: "unsupported mode", className: className)

        XCTAssertEqual(exception.message, "unsupported mode")
    }

    func testGenericFailureDefaultsToServerError() {
        let exception = GenericFailure(className: className)

        XCTAssertEqual(exception.errorCode, OpenID4VPErrorCodes.serverError)
        XCTAssertEqual(exception.message, "Unknown error occurred ")
    }

    func testGenericFailureAppendsProvidedMessage() {
        let exception = GenericFailure(message: "boom", className: className)

        XCTAssertEqual(exception.message, "Unknown error occurred boom")
    }

    func testGenericFailureHonoursExplicitErrorCode() {
        let exception = GenericFailure(
            errorCode: "invalid_request",
            message: "boom",
            className: className
        )

        XCTAssertEqual(exception.errorCode, "invalid_request")
    }

    func testInvalidTypePassesMessageThrough() {
        let exception = InvalidType(message: "wrong type", className: className)

        XCTAssertEqual(exception.message, "wrong type")
    }

    func testMismatchingClientIDInRequestHasFixedMessage() {
        let exception = MismatchingClientIDInRequest(className: className)

        XCTAssertEqual(
            exception.message,
            "Client Id mismatch in Authorization Request parameter and the Request Object"
        )
    }

    func testMismatchingClientIdSchemeInRequestHasFixedMessage() {
        let exception = MismatchingClientIdSchemeInRequest(className: className)

        XCTAssertEqual(
            exception.message,
            "Client Id Scheme mismatch in Authorization Request parameter and the Request Object"
        )
    }

    func testUnsupportedKeyExchangeAlgorithmHasFixedMessage() {
        let exception = UnsupportedKeyExchangeAlgorithm(className: className)

        XCTAssertEqual(exception.message, "Required Key exchange algorithm is not supported")
    }

    func testKeyAgreementFailedPrefixesMessage() {
        let exception = KeyAgreementFailed(message: "curve mismatch", className: className)

        XCTAssertEqual(exception.message, "Key agreement failed. - curve mismatch")
    }

    func testPublicKeyConversionFailedUsesDefaultMessage() {
        let exception = PublicKeyConversionFailed(className: className)

        XCTAssertEqual(exception.message, "Public key Data conversion from base64 failed.")
    }

    func testPublicKeyConversionFailedHonoursCustomMessage() {
        let exception = PublicKeyConversionFailed(message: "custom", className: className)

        XCTAssertEqual(exception.message, "custom")
    }

    func testInvalidEncryptionKeySizeHasFixedMessage() {
        let exception = InvalidEncryptionKeySize(className: className)

        XCTAssertEqual(exception.message, "Invalid Key size provided for encryption.")
    }

    func testUnsupportedHttpMethodUsesRequestUriMethodCode() {
        let exception = UnsupportedHttpMethod(message: "PATCH", className: className)

        XCTAssertEqual(exception.errorCode, OpenID4VPErrorCodes.invalidRequestUriMethod)
        XCTAssertEqual(exception.message, "Unsupported HTTP method: PATCH")
    }

    func testUnsupportedSignatureAlgorithmPassesMessageThrough() {
        let exception = UnsupportedSignatureAlgorithm(message: "ES999", className: className)

        XCTAssertEqual(exception.message, "ES999")
    }

    func testBase64DecodingFailedPassesMessageThrough() {
        let exception = Base64DecodingFailed(message: "not base64", className: className)

        XCTAssertEqual(exception.message, "not base64")
    }

    func testUnsupportedTypeDecodingPassesMessageThrough() {
        let exception = UnsupportedTypeDecoding(message: "unknown type", className: className)

        XCTAssertEqual(exception.message, "unknown type")
    }

    func testUtf8EncodingFailedIncludesFieldPath() {
        let exception = UTF8EncodingFailed(fieldPath: "nonce", className: className)

        XCTAssertEqual(exception.message, "Failed to convert nonce string to UTF-8 data")
    }

    func testAccessDeniedUsesAccessDeniedCode() {
        let exception = AccessDenied(message: "denied", className: className)

        XCTAssertEqual(exception.errorCode, OpenID4VPErrorCodes.accessDenied)
        XCTAssertEqual(exception.message, "denied")
    }

    func testInvalidTransactionDataUsesTransactionDataCode() {
        let exception = InvalidTransactionData(message: "bad txn", className: className)

        XCTAssertEqual(exception.errorCode, OpenID4VPErrorCodes.invalidTransactionData)
        XCTAssertEqual(exception.message, "bad txn")
    }

    func testUnsupportedOperationExceptionDefaultsToUnsupportedOperation() {
        let exception = UnsupportedOperationException(message: "nope", className: className)

        XCTAssertEqual(exception.errorCode, "unsupported_operation")
        XCTAssertEqual(exception.message, "nope")
    }

    func testUnsupportedOperationExceptionHonoursExplicitCode() {
        let exception = UnsupportedOperationException(
            message: "nope",
            className: className,
            code: "invalid_request"
        )

        XCTAssertEqual(exception.errorCode, "invalid_request")
    }

    func testErrorDispatchFailurePrefixesMessage() {
        let exception = ErrorDispatchFailure(message: "timeout", className: className)

        XCTAssertEqual(exception.errorCode, OpenID4VPErrorCodes.errorDispatchFailure)
        XCTAssertEqual(exception.message, "Failed to send error to verifier: timeout")
    }

    func testVerifiablePresentationConstructionFailureWrapsCause() {
        let exception = VerifiablePresentationConstructionFailure(
            cause: SampleCause(),
            className: className
        )

        XCTAssertEqual(exception.errorCode, OpenID4VPErrorCodes.serverError)
        XCTAssertEqual(
            exception.message,
            "The wallet encountered an internal error while preparing the presentation."
        )
        XCTAssertTrue(exception.cause is SampleCause)
    }

    func testAuthorizationResponseConstructionFailureWrapsCause() {
        let exception = AuthorizationResponseConstructionFailure(
            cause: SampleCause(),
            className: className
        )

        XCTAssertEqual(exception.errorCode, OpenID4VPErrorCodes.serverError)
        XCTAssertEqual(
            exception.message,
            "The wallet encountered an internal error while preparing the authorization response."
        )
        XCTAssertTrue(exception.cause is SampleCause)
    }

    func testSubclassesInheritErrorDescriptionAndErrorResponse() {
        let exception = InvalidVerifier(message: "unknown verifier", className: className)

        XCTAssertEqual(exception.errorDescription, "unknown verifier")
        XCTAssertEqual(exception.description, "invalid_client : unknown verifier")
        XCTAssertEqual(
            exception.toErrorResponse(),
            ["error": "invalid_client", "error_description": "unknown verifier"]
        )
    }
}
