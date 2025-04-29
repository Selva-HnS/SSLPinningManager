// The Swift Programming Language
// https://docs.swift.org/swift-book

import Foundation
import Security
import CommonCrypto

private let rsa2048Asn1Header: [UInt8] = [
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
]

private let rsa3072Asn1Header: [UInt8] = [
    0x30, 0x82, 0x01, 0xA2, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
    0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x8F, 0x00
]

private let rsa4096Asn1Header: [UInt8] = [
    0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00
]

private let ecDsaSecp256r1Asn1Header: [UInt8] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00
]

private let ecDsaSecp384r1Asn1Header: [UInt8] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00
]

public let SSLPingKeys = "sslpingkeys"
public let SSLSubDomains = "sslsubdomains"

@MainActor
open class SSLPinningController {
    public static let shared = SSLPinningController()
    var configuration:[String:[String:[String]]]?
    public func setCofiGuration(configuration:[String:[String:[String]]]) {
        self.configuration = configuration
    }
    
    //MARK: Evaluate the server with challenge
    public func evaluateTrust(challenge:URLAuthenticationChallenge,completion:@escaping(_ success:Bool,_ keys:[String]) -> Void) {
        if let serverTrust = challenge.protectionSpace.serverTrust, let configuration = configuration {
            let serverHostname = challenge.protectionSpace.host;
            let certificateChainLen = SecTrustGetCertificateCount(serverTrust)
            let fromlast = certificateChainLen - 1
            let serverName = self.getdomainName(serverHostname: serverHostname)
            var keys = [String]()
            if let servertoCheck = configuration[serverName],let keystoCheck = servertoCheck[SSLPingKeys] {
                var status = false
                for i in 0 ..< certificateChainLen {
                    if !status {
                        if #available(iOS 15.0, *) {
                            // use the feature only available in iOS 9
                            // for ex. UIStackView
                            if let certs = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate] {
                                let certificate = certs[fromlast - i]
                                if let key = self.getPublicKey(from: certificate) {
                                    keys.append(key)
                                    status = keystoCheck.contains(key)
                                }
                            }
                        } else {
                            if let certificate = SecTrustGetCertificateAtIndex(serverTrust, fromlast - i) {
                                if let key = self.getPublicKey(from: certificate) {
                                    keys.append(key)
                                    status = keystoCheck.contains(key)
                                }
                            }
                        }
                    }
                }
                completion(status,keys)
            } else {
                completion(true,[])
            }
        } else {
            completion(true, [])
        }
    }

    //MARK: Get Domain Name
    func getdomainName(serverHostname:String) -> String{
        if let configuration = configuration {
            if configuration[serverHostname] == nil {
                for (key, value) in configuration {
                    let subdomains = value[SSLSubDomains] ?? []
                    if subdomains.contains(serverHostname) {
                        return key
                    }
                }
            }
        }
        return serverHostname
    }
    
    //MARK: Get Public Key
    func getPublicKey(from certificate: SecCertificate?) -> String? {
        if let certificate = certificate {
            
            guard let publicKey = self.copyPublicKey(from: certificate) else {
                print("Error - could not copy the public key from the certificate");
                return nil;
            }
            guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as? Data else {
                print("Error - could not extract the public key bytes");
                return nil;
            }
            
            
            guard let attributes = SecKeyCopyAttributes(publicKey) as? [CFString: Any] else {
                print("Error - could not extract the public key bytes from attributes");
                return nil
            }
            
            guard let publicKeyType = attributes[kSecAttrKeyType] as? String else {
                print("Error - could not extract the public key type");
                return nil
            }
            guard let publicKeysize = attributes[kSecAttrKeySizeInBits] as? NSNumber  else {
                print("Error - could not extract the public key size");
                return nil
            }
            
            if (!isKeySupported(publicKeyType: publicKeyType, publicKeySize: publicKeysize))
            {
                print("Error - public key algorithm or length is not supported");
                return nil;
            }
            
            
            let asn1HeaderBytes = self.getAsn1HeaderBytes(publicKeyType: publicKeyType, publicKeySize: publicKeysize);
            let sha = Sha256()
            sha.update(data: Data(asn1HeaderBytes))
            sha.update(data: publicKeyData)
            return sha.final().base64EncodedString();
        }
        return nil
    }
    
    //MARK: Check Key is Supported
    func isKeySupported(publicKeyType:String!, publicKeySize:NSNumber!) -> Bool
    {
        if ((publicKeyType == (kSecAttrKeyTypeRSA as String))) && (publicKeySize.intValue == 2048)
        {
            return true
        }
        else if ((publicKeyType == (kSecAttrKeyTypeRSA as String))) && (publicKeySize.intValue == 3072)
        {
            return true
        }
        else if ((publicKeyType == (kSecAttrKeyTypeRSA as String))) && (publicKeySize.intValue == 4096)
        {
            return true
        }
        else if ((publicKeyType == (kSecAttrKeyTypeECSECPrimeRandom as String))) && (publicKeySize.intValue == 256)
        {
            return true
        }
        else if ((publicKeyType == (kSecAttrKeyTypeECSECPrimeRandom as String))) && (publicKeySize.intValue == 384)
        {
            return true
        }
        return false
    }
    
    //MARK: Copy public Key From Certificate
    func copyPublicKey(from certificate: SecCertificate?) -> SecKey? {
        var status: OSStatus?

        // Create an X509 trust using the using the certificate
        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        if let certificate = certificate {
            status = SecTrustCreateWithCertificates(certificate, policy, &trust)
        }

        if status != errSecSuccess {
            print("Could not create trust from certificate")
            return nil
        }

        // Get a public key reference for the certificate from the trust
        // The certificate chain must be evaluated first in order to be able
        // to determine which is the leaf certificate of the chain, and only
        // then SecTrustCopyKey can be called
        let publicKey = self.copyKey(trust)

        return publicKey
    }
    
    //MARK: Copy public Key From servertrust
    func copyKey(_ serverTrust: SecTrust?) -> SecKey? {
        if #available(iOS 14.0, macOS 11.0, tvOS 14.0, watchOS 7.0, *) {
            if let serverTrust {
                return SecTrustCopyKey(serverTrust)
            }
            return nil
        } else {
            //#pragma clang diagnostic push
            //#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            if let serverTrust {
                return SecTrustCopyPublicKey(serverTrust)
            }
            return nil
            //#pragma clang diagnostic pop
        }
    }
    
    
    //MARK: Get Key header
    func getAsn1HeaderBytes(publicKeyType: String, publicKeySize: NSNumber) -> [UInt8] {
        if publicKeyType == (kSecAttrKeyTypeRSA as String) && publicKeySize.intValue == 2048 {
            return rsa2048Asn1Header
        }
        else if publicKeyType == (kSecAttrKeyTypeRSA as String) && publicKeySize.intValue == 3072 {
            return rsa3072Asn1Header
        }
        else if publicKeyType == (kSecAttrKeyTypeRSA as String) && publicKeySize.intValue == 4096 {
            return rsa4096Asn1Header
        }
        else if publicKeyType == (kSecAttrKeyTypeECSECPrimeRandom as String) && publicKeySize.intValue == 256 {
            return ecDsaSecp256r1Asn1Header
        }
        else if publicKeyType == (kSecAttrKeyTypeECSECPrimeRandom as String) && publicKeySize.intValue == 384 {
            return ecDsaSecp384r1Asn1Header
        }
        return []
    }
    
    //MARK: Get Key header size
    func getAsn1HeaderSize(_ publicKeyType: String?, _ publicKeySize: NSNumber?) -> UInt {
        if (publicKeyType == kSecAttrKeyTypeRSA as String) && (publicKeySize?.intValue ?? 0 == 2048) {
            return UInt(MemoryLayout.size(ofValue: rsa2048Asn1Header))
        } else if (publicKeyType == kSecAttrKeyTypeRSA as String) && (publicKeySize?.intValue ?? 0 == 3072) {
            return UInt(MemoryLayout.size(ofValue: rsa3072Asn1Header))
        } else if (publicKeyType == kSecAttrKeyTypeRSA as String) && (publicKeySize?.intValue ?? 0 == 4096) {
            return UInt(MemoryLayout.size(ofValue: rsa4096Asn1Header))
        } else if (publicKeyType == kSecAttrKeyTypeECSECPrimeRandom as String) && (publicKeySize?.intValue ?? 0 == 256) {
            return UInt(MemoryLayout.size(ofValue: ecDsaSecp256r1Asn1Header))
        } else if (publicKeyType == kSecAttrKeyTypeECSECPrimeRandom as String) && (publicKeySize?.intValue ?? 0 == 384) {
            return UInt(MemoryLayout.size(ofValue: ecDsaSecp384r1Asn1Header))
        }
        return 0
    }
}


struct Sha256 {
    let context = UnsafeMutablePointer<CC_SHA256_CTX>.allocate(capacity:1)

    init() {
        CC_SHA256_Init(context)
    }

    func update(data: Data) {
        data.withUnsafeBytes { (bytes: UnsafePointer<Int8>) -> Void in
            let end = bytes.advanced(by: data.count)
            for f in sequence(first: bytes, next: { $0.advanced(by: Int(CC_LONG.max)) }).prefix(while: { (current) -> Bool in current < end})  {
                _ = CC_SHA256_Update(context, f, CC_LONG(Swift.min(f.distance(to: end), Int(CC_LONG.max))))
            }
        }
    }

    func final() -> Data {
        var digest = [UInt8](repeating: 0, count:Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256_Final(&digest, context)

        return Data(bytes: digest)
    }
}

extension Data {
    func sha256() -> Data {
        let s = Sha256()
        s.update(data: self)
        return s.final()
    }
}

extension String {
    func sha256() -> Data {
        return self.data(using: .utf8)!.sha256()
    }
}
