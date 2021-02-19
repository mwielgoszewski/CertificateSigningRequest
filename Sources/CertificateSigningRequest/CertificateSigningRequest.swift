//
//  CertificateSigningRequest.swift
//  CertificateSigningRequest
//
//  Created by Corey Baker on 10/19/16.
//  Copyright © Corey Baker. All rights reserved.
//
//  This is a port of ios-csr by Ales Teska (https://github.com/ateska/ios-csr) 
//  from Objective-c to Swift. Additions have been made to allow SHA256 and SHA512.
//
//  Copyright (C) 2016  Corey Baker
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.

//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

/*
 
 Certification Request Syntax Specification: http://www.ietf.org/rfc/rfc2986.txt
 
 */

import Foundation
#if canImport(Security)
import Security
#endif
import CryptoKit

// swiftlint:disable:next type_body_length
public class CertificateSigningRequest: NSObject {
    private let objectCommonName: [UInt8] = [0x06, 0x03, 0x55, 0x04, 0x03]
    private let objectCountryName: [UInt8] = [0x06, 0x03, 0x55, 0x04, 0x06]
    private let objectDescription: [UInt8] = [0x06, 0x03, 0x55, 0x04, 0x0D]
    private let objectEmailAddress: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01]
    private let objectLocalityName: [UInt8] = [0x06, 0x03, 0x55, 0x04, 0x07]
    private let objectOrganizationName: [UInt8] = [0x06, 0x03, 0x55, 0x04, 0x0A]
    private let objectOrganizationalUnitName: [UInt8] = [0x06, 0x03, 0x55, 0x04, 0x0B]
    private let objectStateOrProvinceName: [UInt8] = [0x06, 0x03, 0x55, 0x04, 0x08]
    
    private let objectExtensionRequest: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E]    // 1.2.840.113549.1.9.14
    private let objectSubjectKeyIdentifier: [UInt8] = [0x06, 0x03, 0x55, 0x1D, 0x0E]    // 2.5.29.14
    private let objectKeyUsage: [UInt8] = [0x06, 0x03, 0x55, 0x1D, 0x0F]                // 2.5.29.15
    private let objectSubjectAlternativeName: [UInt8] = [0x06, 0x03, 0x55, 0x1D, 0x11]  // 2.5.29.17
    private let objectBasicConstraints: [UInt8] = [0x06, 0x03, 0x55, 0x1D, 0x13]        // 2.5.29.19
    private let objectExtendedKeyUsage: [UInt8] = [0x06, 0x03, 0x55, 0x1D, 0x25]        // 2.5.29.37
    
    private let sequenceTag: UInt8 = 0x30
    private let setTag: UInt8 = 0x31
    private let commonName: String?
    private let countryName: String?
    private let emailAddress: String?
    private let csrDescription: String?
    private let localityName: String?
    private let organizationName: String?
    private let organizationUnitName: String?
    private let stateOrProvinceName: String?
    private var keyAlgorithm: KeyAlgorithm!
    private var subjectDER: Data?

    public init(commonName: String? = nil, organizationName: String? = nil,
                organizationUnitName: String? = nil, countryName: String? = nil,
                stateOrProvinceName: String? = nil, localityName: String? = nil,
                emailAddress: String? = nil, description: String? = nil,
                keyAlgorithm: KeyAlgorithm) {
        self.commonName = commonName
        self.organizationName = organizationName
        self.organizationUnitName = organizationUnitName
        self.countryName = countryName
        self.stateOrProvinceName = stateOrProvinceName
        self.localityName = localityName
        self.emailAddress = emailAddress
        self.csrDescription = description
        self.keyAlgorithm = keyAlgorithm
        super.init()
    }

    public convenience override init() {
        self.init(commonName: nil, organizationName: nil, organizationUnitName: nil,
                  countryName: nil, stateOrProvinceName: nil, localityName: nil,
                  keyAlgorithm: KeyAlgorithm.rsa(signatureType: .sha512))
    }

    public convenience init(keyAlgorithm: KeyAlgorithm) {
        self.init(commonName: nil, organizationName: nil, organizationUnitName: nil,
                  countryName: nil, stateOrProvinceName: nil, localityName: nil,
                  keyAlgorithm: keyAlgorithm)
    }

    public func build(_ publicKeyBits: Data, privateKey: SecKey, publicKey: SecKey?=nil) -> Data? {
        let certificationRequestInfo = buldCertificationRequestInfo(publicKeyBits)
        var signature = [UInt8](repeating: 0, count: 256)
        var signatureLen: Int = signature.count

        var error: Unmanaged<CFError>?
        guard let signatureData = SecKeyCreateSignature(privateKey,
                                                        keyAlgorithm.signatureAlgorithm,
                                                        certificationRequestInfo as CFData, &error) as Data? else {
            if error != nil {
                print("Error in creating signature: \(error!.takeRetainedValue())")
            }
            return nil
        }
        signatureData.copyBytes(to: &signature, count: signatureData.count)
        signatureLen = signatureData.count
        if publicKey != nil {
            if !SecKeyVerifySignature(publicKey!, keyAlgorithm.signatureAlgorithm,
                                      certificationRequestInfo as CFData, signatureData as CFData, &error) {
                print(error!.takeRetainedValue())
                return nil
            }
        }

        var certificationRequest = Data(capacity: 1024)
        certificationRequest.append(certificationRequestInfo)
        let shaBytes = keyAlgorithm.sequenceObjectEncryptionType
        certificationRequest.append(shaBytes, count: shaBytes.count)

        var signData = Data(capacity: 257)
        let zero: UInt8 = 0 // Prepend zero
        signData.append(zero)
        signData.append(signature, count: signatureLen)
        appendBITSTRING(signData, into: &certificationRequest)

        enclose(&certificationRequest, by: sequenceTag) // Enclose into SEQUENCE

        return certificationRequest
    }

    public func buildAndEncodeDataAsString(_ publicKeyBits: Data, privateKey: SecKey,
                                           publicKey: SecKey?=nil) -> String? {

        guard let buildData = self.build(publicKeyBits, privateKey: privateKey, publicKey: publicKey) else {
            return nil
        }

        return buildData.base64EncodedString(options: NSData.Base64EncodingOptions(rawValue: 0))
            .addingPercentEncoding(withAllowedCharacters: CharacterSet.urlQueryAllowed)

    }

    public func buildCSRAndReturnString(_ publicKeyBits: Data, privateKey: SecKey, publicKey: SecKey?=nil) -> String? {

        guard let csrString = self.buildAndEncodeDataAsString(publicKeyBits,
                                                              privateKey: privateKey, publicKey: publicKey) else {
            return nil
        }

        let head = "-----BEGIN CERTIFICATE REQUEST-----\n"
        let foot = "-----END CERTIFICATE REQUEST-----\n"
        var isMultiple = false
        var newCSRString = head

        //Check if string size is a multiple of 64
        if csrString.count % 64 == 0 {
            isMultiple = true
        }

        for (integer, character) in csrString.enumerated() {
            newCSRString.append(character)

            if (integer != 0) && ((integer + 1) % 64 == 0) {
                newCSRString.append("\n")
            }

            if (integer == csrString.count-1) && !isMultiple {
                newCSRString.append("\n")
            }

        }

        newCSRString += foot

        return newCSRString
    }

    func buldCertificationRequestInfo(_ publicKeyBits: Data) -> Data {
        var certificationRequestInfo = Data(capacity: 1024)

        //Add version
        let version: [UInt8] = [0x02, 0x01, 0x00] // ASN.1 Representation of integer with value 1
        certificationRequestInfo.append(version, count: version.count)

        //Add subject
        var subject = Data(capacity: 256)

        if countryName != "", let countryName = countryName {
            appendSubjectItem(objectCountryName, value: countryName, into: &subject)
        }

        if stateOrProvinceName != "", let stateOrProvinceName = stateOrProvinceName {
            appendSubjectItem(objectStateOrProvinceName, value: stateOrProvinceName, into: &subject)
        }

        if localityName != "", let localityName = localityName {
            appendSubjectItem(objectLocalityName, value: localityName, into: &subject)
        }

        if organizationName != "", let organizationName = organizationName {
            appendSubjectItem(objectOrganizationName, value: organizationName, into: &subject)
        }

        if organizationUnitName != "", let organizationUnitName = organizationUnitName {
            let units = organizationUnitName.split(separator: ";")
            for unit in units {
                let unit = String(unit).trimmingCharacters(in: .whitespacesAndNewlines)
                appendSubjectItem(objectOrganizationalUnitName, value: unit, into: &subject)
            }
        }

        if commonName != "", let commonName = commonName {
            appendSubjectItem(objectCommonName, value: commonName, into: &subject)
        }

        if emailAddress != "", let emailAddress = emailAddress {
            let email = String(emailAddress.split(separator: ";").first!).trimmingCharacters(in: .whitespacesAndNewlines)
            appendSubjectItem(objectEmailAddress, value: email, into: &subject, encoding: .ascii)
        }

        if csrDescription != "", let description = csrDescription {
            appendSubjectItem(objectDescription, value: description, into: &subject)
        }

        enclose(&subject, by: sequenceTag)// Enclose into SEQUENCE
        subjectDER = subject
        certificationRequestInfo.append(subject)

        //Add public key info
        let publicKeyInfo = buildPublicKeyInfo(publicKeyBits)
        certificationRequestInfo.append(publicKeyInfo)
                
        // Add attributes
        let extensionRequest = buildExtensionRequest(publicKeyBits)
        if extensionRequest == nil {
            certificationRequestInfo.append([0xA0, 0x00], count: 2)
        } else {
            certificationRequestInfo.append(0xA0)
            appendDERLength(extensionRequest!.count, into: &certificationRequestInfo)
            certificationRequestInfo.append(extensionRequest!)
        }
        
        enclose(&certificationRequestInfo, by: sequenceTag) // Enclose into SEQUENCE
        return certificationRequestInfo
    }

    // Utility class methods ...
    func buildPublicKeyInfo(_ publicKeyBits: Data) -> Data {

        var publicKeyInfo = Data(capacity: 390)

        switch keyAlgorithm! {
        case .rsa:
            publicKeyInfo.append(objectRSAEncryptionNULL, count: objectRSAEncryptionNULL.count)
        case .ec:
            publicKeyInfo.append(objectECPubicKey, count: objectECPubicKey.count)
            publicKeyInfo.append(objectECEncryptionNULL, count: objectECEncryptionNULL.count)
        }

        enclose(&publicKeyInfo, by: sequenceTag) // Enclose into SEQUENCE

        var publicKeyASN = Data(capacity: 260)
        switch keyAlgorithm! {
        case .ec:
            let key = getPublicKey(publicKeyBits)
            publicKeyASN.append(key)

        default:

            let mod = getPublicKeyMod(publicKeyBits)
            let integer: UInt8 = 0x02 //Integer
            publicKeyASN.append(integer)
            appendDERLength(mod.count, into: &publicKeyASN)
            publicKeyASN.append(mod)

            let exp = getPublicKeyExp(publicKeyBits)
            publicKeyASN.append(integer)
            appendDERLength(exp.count, into: &publicKeyASN)
            publicKeyASN.append(exp)

            enclose(&publicKeyASN, by: sequenceTag)// Enclose into ??
        }

        prependByte(0x00, into: &publicKeyASN) //Prepend 0 (?)
        appendBITSTRING(publicKeyASN, into: &publicKeyInfo)

        enclose(&publicKeyInfo, by: sequenceTag) // Enclose into SEQUENCE

        return publicKeyInfo
    }
    
    func buildExtensionRequest(_ publicKeyBits: Data) -> Data? {
        var extensionRequest = Data()
        extensionRequest.append(objectExtensionRequest, count: objectExtensionRequest.count)
        var extensions = Data()
        
        // Key Usage
        
        var keyUsage = Data()
        keyUsage.append(objectKeyUsage, count: objectKeyUsage.count)
        appendBoolean(true, into: &keyUsage)
        let keyUsageBits = Data([0x3,0x2,0x3,0x88])
        appendOCTETSTRING(keyUsageBits, into: &keyUsage)
        enclose(&keyUsage, by: sequenceTag)
        extensions.append(keyUsage)

        // Basic Constraints

        var basicConstraint = Data()
        //appendBoolean(false, into: &basicConstraint)
        // if ca is true, add pathLenConstraint (integer)
        enclose(&basicConstraint, by: sequenceTag)
        let basicConstraints = buildExtension(objectBasicConstraints, extnValue: basicConstraint, critical: true)
        extensions.append(basicConstraints)

        // Subject Key Identifier

        if #available(OSX 10.15, *) {
            var publicKeyHash = Data()
            publicKeyHash.append(0x04) // octet string type
            publicKeyHash.append(0x14) // 20 bytes sha-1
            publicKeyHash.append(contentsOf: Insecure.SHA1.hash(data: publicKeyBits))
            let subjectKeyIdentifier = buildExtension(objectSubjectKeyIdentifier, extnValue: publicKeyHash)
            extensions.append(subjectKeyIdentifier)

        } else {
            // Fallback on earlier versions
        }

        // Extended Key Usage

        var ekus = Data()
        ekus.append(contentsOf: [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]) // clientAuth
        enclose(&ekus, by: sequenceTag)
        let extendedKeyUsage = buildExtension(objectExtendedKeyUsage, extnValue: ekus)
        extensions.append(extendedKeyUsage)

        // Subject Alternative Names
        
        if emailAddress != "" {
            var san = Data()
            for email in emailAddress!.split(separator: ";") {
                let email = String(email).trimmingCharacters(in: .whitespacesAndNewlines)
                // 0x81 (tag class context-specific, 8th bit set, tag 1 for rfc8222 names)
                san.append(0x81)
                appendDERLength(email.lengthOfBytes(using: .ascii), into: &san)
                san.append(email.data(using: .ascii)!)
            }
            enclose(&san, by: sequenceTag)
                
            let subjectAltNames = buildExtension(objectSubjectAlternativeName, extnValue: san)
            extensions.append(subjectAltNames)
        }
        
        // Wrap it up
        
        enclose(&extensions, by: sequenceTag)
        enclose(&extensions, by: setTag)
        extensionRequest.append(extensions)
        enclose(&extensionRequest, by: sequenceTag)
        return extensionRequest
    }
    
    func buildExtension(_ extnId: [UInt8], extnValue: Data, critical: Bool? = nil) -> Data {
        var extn = Data()
        extn.append(extnId, count: extnId.count)
        if critical != nil {
            appendBoolean(critical!, into: &extn)
        }
        appendOCTETSTRING(extnValue, into: &extn)
        enclose(&extn, by: sequenceTag)
        return extn
    }

    func appendSubjectItem(_ what: [UInt8], value: String, into: inout Data, encoding: String.Encoding = .utf8) {

        if what.count != 5 && what.count != 11 {
            print("Error: appending to a non-subject item")
            return
        }

        var subjectItem = Data(capacity: 128)

        subjectItem.append(what, count: what.count)
        if encoding == .utf8 {
            appendUTF8String(string: value, into: &subjectItem)
        } else {
            appendStringOfTagType(strType: 0x16, string: value, into: &subjectItem, encoding: encoding)
        }
        enclose(&subjectItem, by: sequenceTag)
        enclose(&subjectItem, by: setTag)

        into.append(subjectItem)
    }

    func appendUTF8String(string: String, into: inout Data) {

        let strType: UInt8 = 0x0C //UTF8STRING

        into.append(strType)
        appendDERLength(string.lengthOfBytes(using: String.Encoding.utf8), into: &into)
        into.append(string.data(using: String.Encoding.utf8)!)
    }
    
    func appendStringOfTagType(strType: UInt8, string: String, into: inout Data, encoding: String.Encoding = .utf8) {
        into.append(strType)
        appendDERLength(string.lengthOfBytes(using: encoding), into: &into)
        into.append(string.data(using: encoding)!)
    }

    func appendDERLength(_ length: Int, into: inout Data) {

        assert(length < 0x8000)

        if length < 128 {
            let dLength = UInt8(length)
            into.append(dLength)

        } else if length < 0x100 {

            var dLength: [UInt8] = [0x81, UInt8(length & 0xFF)]
            into.append(&dLength, count: dLength.count)

        } else if length < 0x8000 {

            let preRes: UInt = UInt(length & 0xFF00)
            let res = UInt8(preRes >> 8)
            var dLength: [UInt8] = [0x82, res, UInt8(length & 0xFF)]
            into.append(&dLength, count: dLength.count)
        }
    }
    
    func appendBoolean(_ value: Bool, into: inout Data) {
        into.append(contentsOf: [0x01, 0x01])   //BOOLEAN w/length 1
        if value {
            into.append(0xff)
        } else {
            into.append(0x00)
        }
    }

    func appendBITSTRING(_ data: Data, into: inout Data) {

        let strType: UInt8 = 0x03 //BIT STRING
        into.append(strType)
        appendDERLength(data.count, into: &into)
        into.append(data)
    }
    
    func appendOCTETSTRING(_ data: Data, into: inout Data) {
        let strType: UInt8 = 0x04 //OCTET STRING
        into.append(strType)
        appendDERLength(data.count, into: &into)
        into.append(data)
    }

    // swiftlint:disable:next identifier_name
    func enclose(_ data: inout Data, by: UInt8) {

        var newData = Data(capacity: data.count + 4)

        newData.append(by)
        appendDERLength(data.count, into: &newData)
        newData.append(data)

        data = newData
    }

    func prependByte(_ byte: UInt8, into: inout Data) {

        var newData = Data(capacity: into.count + 1)

        newData.append(byte)
        newData.append(into)

        into = newData
    }

    func getPublicKey(_ publicKeyBits: Data) -> Data {

        //Current only supports uncompressed keys, 65=1+32+32
        var iterator = 0

        _ = derEncodingSpecificSize(publicKeyBits, at: &iterator, numOfBytes: 8)

        let range: Range<Int> = 0 ..< 65

        return publicKeyBits.subdata(in: range)
    }

    // swiftlint:disable:next line_length
    // From http://stackoverflow.com/questions/3840005/how-to-find-out-the-modulus-and-exponent-of-rsa-public-key-on-iphone-objective-c

    func getPublicKeyExp(_ publicKeyBits: Data) -> Data {

        var iterator = 0

        iterator+=1 // TYPE - bit stream - mod + exp
        _ = derEncodingGetSizeFrom(publicKeyBits, at: &iterator) // Total size

        iterator+=1 // TYPE - bit stream mod
        let modSize = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)
        iterator += modSize

        iterator+=1 // TYPE - bit stream exp
        let expSize = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)

        let range: Range<Int> = iterator ..< (iterator + expSize)

        return publicKeyBits.subdata(in: range)
    }

    func getPublicKeyMod(_ publicKeyBits: Data) -> Data {

        var iterator = 0

        iterator+=1 // TYPE - bit stream - mod + exp
        _ = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)

        iterator+=1 // TYPE - bit stream mod
        let modSize = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)

        let range: Range<Int> = iterator ..< (iterator + modSize)

        return publicKeyBits.subdata(in: range)
    }

    func derEncodingSpecificSize(_ buf: Data, at iterator: inout Int, numOfBytes: Int) -> Int {

        var data = [UInt8](repeating: 0, count: buf.count)
        buf.copyBytes(to: &data, count: buf.count)

        if data[0] != 0x04 {
            print("Error, framework only supports uncompressed keys")
        }

        return buf.count
    }

    func derEncodingGetSizeFrom(_ buf: Data, at iterator: inout Int) -> Int {

        var data = [UInt8](repeating: 0, count: buf.count)
        buf.copyBytes(to: &data, count: buf.count)

        var itr = iterator
        var numOfBytes = 1
        var ret = 0

        if data[itr] > 0x80 {
            numOfBytes = Int((data[itr] - 0x80))
            itr += 1
        }

        for index in 0 ..< numOfBytes {
            ret = (ret * 0x100) + Int(data[itr + index])
        }

        iterator = itr + numOfBytes

        return ret
    }
    
} // swiftlint:disable:this file_length
