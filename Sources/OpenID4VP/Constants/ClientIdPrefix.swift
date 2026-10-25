import Foundation

public enum ClientIdPrefix: String, Codable, CaseIterable {
    case preRegistered = "pre-registered"
    case redirectUri = "redirect_uri"
    case decentralizedIdentifier = "decentralized_identifier"
    case x509Hash = "x509_hash"

    public static func fromValue(_ value: String) -> ClientIdPrefix? {
        return ClientIdPrefix(rawValue: value)
    }

    // Returns nil when Draft 23 defines no Client Identifier Scheme for the prefix
    static func toClientIdScheme(_ clientIdPrefix: ClientIdPrefix) -> String? {
        switch clientIdPrefix {
        case .preRegistered:
            return ClientIdScheme.preRegistered.rawValue
        case .redirectUri:
            return ClientIdScheme.redirectUri.rawValue
        case .decentralizedIdentifier:
            return ClientIdScheme.did.rawValue
        case .x509Hash:
            return nil
        }
    }
}

internal enum ClientIdScheme: String, Codable, CaseIterable {
    case preRegistered = "pre-registered"
    case redirectUri = "redirect_uri"
    case did = "did"
    
    public static func fromValue(_ value: String) -> ClientIdScheme? {
        return ClientIdScheme(rawValue: value)
    }
}
