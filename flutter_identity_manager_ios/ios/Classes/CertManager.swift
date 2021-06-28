//
//  CertManager.swift
//  flutter_identity_manager
//
//  Created by Nils Wieler on 30.05.21.
//

import Foundation
import OpenSSL


@available(iOS 10.0, *)
class CertManager{
    
    // certData is in DER format. Storing the certificate creates automatically an identity if
    // corresponding key is in the keychain
    public static func createIdentity(certData: Data, label: String) -> Bool{
        guard let certificate = SecCertificateCreateWithData(nil, certData as CFData) else {
            return false;
        };
        let addQuery: [String: Any] = [kSecClass as String: kSecClassCertificate,kSecValueRef as String: certificate, kSecAttrLabel as String: label];
        let status = SecItemAdd(addQuery as CFDictionary, nil);
        guard status == errSecSuccess else {
            return false;
        }
        return true;
    }
    
    public static func loadIdentity(tag: String, p12Name: String, p12Password:String) -> Data?{
        // Get identity from Keychain
        let getQuery : [String: Any] = [kSecClass as String: kSecClassIdentity, kSecAttrApplicationTag as String: tag.data(using: .utf8)!,kSecReturnRef as String: true];
        var item: CFTypeRef?;
        let status = SecItemCopyMatching(getQuery as CFDictionary, &item);
        guard status == errSecSuccess else {
            print(status);
            return nil;
        }
        // Extract key from identity
        let identity = item as! SecIdentity;
        var keyItem: SecKey?;
        let keyStatus = SecIdentityCopyPrivateKey(identity, &keyItem);
        guard keyStatus == errSecSuccess else {
            print(keyStatus);
            return nil;
        }
        // Extract cert from identity
        var certItem: SecCertificate?;
        let certStatus = SecIdentityCopyCertificate(identity, &certItem);
        guard certStatus == errSecSuccess else {
            print(certStatus);
            return nil;
        }
        return createPKCS12(key: keyItem!, cert: certItem!,p12Name: p12Name,p12Password: p12Password);
    }
    
    
    private static func createPKCS12(key: SecKey, cert:SecCertificate, p12Name: String, p12Password: String) -> Data?{
        // Read certificate
        // Convert sec certificate to DER certificate
        let derCertificate = SecCertificateCopyData(cert)
        var certificatePointer = CFDataGetBytePtr(derCertificate)
        let certificateLength = CFDataGetLength(derCertificate)
        let certificate = d2i_X509(nil, &certificatePointer, certificateLength)
        //X509_print_fp(stderr,certificate);
        
        var error: Unmanaged<CFError>?;
        guard let derKey = SecKeyCopyExternalRepresentation(key, &error) else {
            print(error!.takeRetainedValue() as Error);
            return nil;
        }
        var keyPointer = CFDataGetBytePtr(derKey);
        let keyLength = CFDataGetLength(derKey);
        let privateKey = d2i_AutoPrivateKey(nil,&keyPointer, keyLength);
        //RSA_print_fp(stderr,privateKey,0);
        
        // Check if private key matches certificate
        guard X509_check_private_key(certificate, privateKey) == 1 else {
            print("Cert does not match key");
            return nil;
        }
        // Set OpenSSL parameters
        //OPENSSL_add_all_algorithms_noconf()
        //ERR_load_crypto_strings()
        
        // Create P12 keystore
        let passPhrase = UnsafeMutablePointer(mutating: (p12Password as NSString).utf8String)
        let name = UnsafeMutablePointer(mutating: (p12Name as NSString).utf8String)
        guard let p12 = PKCS12_create(passPhrase, name, privateKey, certificate, nil, 0, 0, 0, 0, 0) else {
            ERR_print_errors_fp(stderr)
            return nil;
        }
        var p12Data :UnsafeMutablePointer<UInt8>? = nil;
        defer {
            p12Data?.deallocate();
        }
        let p12Length = i2d_PKCS12(p12, &p12Data);
        //return p12Data.pointee?.pointee as Data;
        if(p12Data == nil){
            return nil;
        }
        let out = Data(bytes: p12Data!, count: Int(p12Length));
        
        return out;
    }
    
    
    public static func loadPublicKey(tag: String) -> Data?{
        let getQuery : [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag.data(using: .utf8)!,kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecReturnRef as String: true];
        var item: CFTypeRef?;
        let status = SecItemCopyMatching(getQuery as CFDictionary, &item);
        guard status == errSecSuccess else {
            print(status);
            return nil;
        }
        guard let publicKey = SecKeyCopyPublicKey(item as! SecKey) else {
            return nil;
        }
        return CertManager.publicKeyToData(publicKey: publicKey);
    }
    
    public static func generateKey(keyAttributes: KeyAttributes) -> Data?{
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(keyAttributes.asDictionary
                                              , &error) else {
            print(error!.takeRetainedValue() as Error);
            return nil;
        }
        guard let publicKey = SecKeyCopyPublicKey(key) else
        {
            return nil;
        }
        return CertManager.publicKeyToData(publicKey: publicKey);
    }
        
    public static func deleteCert(label: String) -> Bool {
        let query: [String: Any] = [kSecClass as String: kSecClassCertificate,
                                       kSecAttrLabel as String: label]
        let status = SecItemDelete(query as CFDictionary);
        guard status == errSecSuccess || status == errSecItemNotFound else {
            print(status);
            return false;
        }
        return true;
    }
    
    public static func deleteKey(tag: String) -> Bool{
        let query : [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag.data(using: .utf8)!,kSecAttrKeyType as String: kSecAttrKeyTypeRSA];
        let status = SecItemDelete(query as CFDictionary);
        guard status == errSecSuccess || status == errSecItemNotFound else {
            print(status);
            return false;
        }
        return true;
    }
    
    private static func publicKeyToData(publicKey: SecKey) -> Data?{
        var error: Unmanaged<CFError>?;
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            return nil;
        }
        return publicKeyData as Data;
    }
    
}


struct KeyAttributes{
    
    private var type : CFString = kSecAttrKeyTypeRSA;
    
    let tag : String;
    
    
    init(tag: String) {
        self.tag = tag;
    }
    var size : Int = 4096;
    var permanent: Bool = true;
 
    
    var asDictionary: CFDictionary {
        get {
            let attributes : [String: Any] = [kSecAttrKeyType as String: type,
                                              kSecAttrKeySizeInBits as String: size,
                                              kSecPrivateKeyAttrs as String: [
                                                kSecAttrIsPermanent as String: permanent,
                                                kSecAttrApplicationTag as String: tag.data(using: .utf8)!
                                              ]
            ];
            return attributes as CFDictionary;
        }
    }
}
