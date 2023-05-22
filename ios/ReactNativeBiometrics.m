//
//  ReactNativeBiometrics.m
//
//  Created by Brandon Hines on 4/3/18.
//

#import "ReactNativeBiometrics.h"
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>
#import <React/RCTConvert.h>

@implementation ReactNativeBiometrics

RCT_EXPORT_MODULE(ReactNativeBiometrics);

RCT_EXPORT_METHOD(isSensorAvailable:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
    LAContext *context = [[LAContext alloc] init];
    NSError *la_error = nil;
    BOOL canEvaluatePolicy = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&la_error];

    if (canEvaluatePolicy) {
        NSString *biometryType = [self getBiometryType:context];
        NSDictionary *result = @{
            @"available": @(YES),
            @"biometryType": biometryType
        };

        resolve(result);
    } else {
        NSString *errorMessage = [NSString stringWithFormat:@"%@", la_error];
        NSDictionary *result = @{
            @"available": @(NO),
            @"error": errorMessage
        };

        resolve(result);
    }
}

- (OSStatus) savePinCode:(NSString *)pincode keyTag:(NSString *)keyTag  {
    CFErrorRef error = NULL;
    //      SecAccessControlCreateFlags flags = applicationPassword ? kSecAccessControlApplicationPassword : kSecAccessControlBiometryAny;
    SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                    kSecAttrAccessibleAlwaysThisDeviceOnly,
                                                                    kSecAccessControlBiometryCurrentSet, &error);
    
    if (sacObject == NULL || error != NULL) {
        NSString *errorString = [NSString stringWithFormat:@"SecItemAdd can't create sacObject: %@", error];
        NSError *e = [NSError errorWithDomain:@"storage_error" code:0 userInfo:@{
            NSDebugDescriptionErrorKey: @{},
            NSLocalizedFailureReasonErrorKey: errorString }];
        @throw e;
    }

    NSData *pincodeData = [pincode dataUsingEncoding:NSUTF8StringEncoding];
    
    NSDictionary *query = @{
        (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrAccount: [self getPinCodeTag:keyTag],
        (id)kSecAttrAccessControl: (__bridge_transfer id)sacObject,
        (id)kSecValueData: pincodeData
    };
    
    return SecItemAdd((__bridge CFDictionaryRef)query, nil);
}

- (NSString *) loadPinCode:(NSString *)keyTag {
    NSDictionary *query = @{
                (id)kSecClass: (id)kSecClassGenericPassword,
                (id)kSecAttrAccount: [self getPinCodeTag:keyTag],
                (id)kSecReturnData: @YES
            };

    NSData *pincodeData = nil;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (void *)&pincodeData);

    if (status == errSecSuccess && pincodeData) {
        NSString *pincode = [[NSString alloc] initWithData:pincodeData encoding:NSUTF8StringEncoding];
        return pincode;
    } else {
        NSString *message = [NSString stringWithFormat:@"Pincode could not be loaded: %@",[self keychainErrorToString:status]];
        NSError *e = [NSError errorWithDomain:@"storage_error" code:0 userInfo:@{
            NSDebugDescriptionErrorKey: @{},
            NSLocalizedFailureReasonErrorKey: message }];
        @throw e;
    }
}

-(OSStatus) deletePinCode:(NSString *)keyTag {
    NSDictionary *deleteQuery = @{
        (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrAccount: [self getPinCodeTag:keyTag],
    };

    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
    return status;
}

- (NSString *) getPinCodeTag: (NSString *) keyTag {
    return [NSString stringWithFormat:@"com.rnbiometrics.biometricKey.password.%@", keyTag];
}

RCT_EXPORT_METHOD(createKeys: (NSDictionary *)params resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *keyTag = [RCTConvert NSString:params[@"keyTag"]];
        NSString *pinCode = [RCTConvert NSString:params[@"keyPassword"]];
        
        NSLog(@"createKeys => PinCode: %@", pinCode);
        LAContext *localAuthenticationContext = [[LAContext alloc] init];
        
        if(pinCode!=nil){
            @try {
                [self savePinCode:pinCode keyTag:keyTag];
            } @catch (NSError *error) {
                NSLog(@"savePinCode error: %@ %@", error.domain, error.localizedFailureReason);
                NSString *message = [NSString stringWithFormat:@"Pincode could not be saved: %@", error];
                return reject(error.domain, message, error);
            }
            
            NSData *theApplicationPassword = [pinCode dataUsingEncoding:NSUTF8StringEncoding];
            [localAuthenticationContext setCredential:theApplicationPassword type:LACredentialTypeApplicationPassword];
        }

        
        CFErrorRef error = NULL;
        SecAccessControlCreateFlags flags = pinCode ? kSecAccessControlApplicationPassword : kSecAccessControlBiometryAny;
        SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                        kSecAttrAccessibleAlwaysThisDeviceOnly,
                                                                        flags, &error);
        
        if (sacObject == NULL || error != NULL) {
            NSString *errorString = [NSString stringWithFormat:@"SecItemAdd can't create sacObject: %@", error];
            reject(@"storage_error", errorString, nil);
            return;
        }
        
        NSData *biometricKeyTag = [self getBiometricKeyTag:keyTag];
        NSDictionary *keyAttributes = @{
            (id)kSecClass: (id)kSecClassKey,
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
            (id)kSecAttrKeySizeInBits: @2048,
            (id)kSecPrivateKeyAttrs: @{
                    (id)kSecAttrIsPermanent: @YES,
                    (id)kSecUseAuthenticationUI: (id)kSecUseAuthenticationUIFail,
                    (id)kSecAttrApplicationTag: biometricKeyTag,
                    (id)kSecAttrAccessControl: (__bridge_transfer id)sacObject,
                    (id)kSecUseAuthenticationContext:localAuthenticationContext,
                    
            }
        };
        
        [self deleteBiometricKey:keyTag];
        NSError *gen_error = nil;
        id privateKey = CFBridgingRelease(SecKeyCreateRandomKey((__bridge CFDictionaryRef)keyAttributes, (void *)&gen_error));
        
        if(privateKey != nil) {
            id publicKey = CFBridgingRelease(SecKeyCopyPublicKey((SecKeyRef)privateKey));
            CFDataRef publicKeyDataRef = SecKeyCopyExternalRepresentation((SecKeyRef)publicKey, nil);
            NSData *publicKeyData = (__bridge NSData *)publicKeyDataRef;
            NSData *publicKeyDataWithHeader = [self addHeaderPublickey:publicKeyData];
            NSString *publicKeyString = [publicKeyDataWithHeader base64EncodedStringWithOptions:0];
            
            NSDictionary *result = @{
                @"publicKey": publicKeyString,
            };
            resolve(result);
        } else {
            NSString *message = [NSString stringWithFormat:@"Key generation error: %@", gen_error];
            reject(@"storage_error", message, nil);
        }
    });
}

RCT_EXPORT_METHOD(deleteKeys: (NSDictionary *)params resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *keyTag = [RCTConvert NSString:params[@"keyTag"]];
        BOOL biometricKeyExists = [self doesBiometricKeyExist:keyTag];
        
        [self deletePinCode:keyTag];
        if (biometricKeyExists) {
            OSStatus status = [self deleteBiometricKey:keyTag];
            
            if (status == noErr) {
                NSDictionary *result = @{
                    @"keysDeleted": @(YES),
                };
                resolve(result);
            } else {
                NSString *message = [NSString stringWithFormat:@"Key not found: %@",[self keychainErrorToString:status]];
                reject(@"deletion_error", message, nil);
            }
        } else {
            NSDictionary *result = @{
                @"keysDeleted": @(NO),
            };
            resolve(result);
        }
    });
}

RCT_EXPORT_METHOD(createSignature: (NSDictionary *)params resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *promptMessage = [RCTConvert NSString:params[@"promptMessage"]];
        NSString *payload = [RCTConvert NSString:params[@"payload"]];
        NSString *pincode = [RCTConvert NSString:params[@"keyPassword"]];
        NSString *keyTag = [RCTConvert NSString:params[@"keyTag"]];
        
        NSData *biometricKeyTag = [self getBiometricKeyTag:keyTag];
        NSMutableDictionary *query = [[NSMutableDictionary alloc] initWithDictionary:@{
                    (id)kSecClass: (id)kSecClassKey,
                    (id)kSecAttrApplicationTag: biometricKeyTag,
                    (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                    (id)kSecReturnRef: @YES
                }];
        NSLog(@"createSignature => PinCode: %@", pincode);
        LAContext *validationContext =  [[LAContext alloc] init];

        @try {
            if(!pincode){
                pincode = [self loadPinCode:keyTag];
            }
        } @catch (NSError *error) {
            NSLog(@"loadPinCode error: %@ %@", error.domain, error.localizedFailureReason);
            return reject(error.domain, error.localizedFailureReason, error);
        }
        
        
        if(pincode){
            NSData *theApplicationPassword = [pincode dataUsingEncoding:NSUTF8StringEncoding];
            [validationContext setCredential:theApplicationPassword type:LACredentialTypeApplicationPassword];

//
//            CFErrorRef error = NULL;
//            SecAccessControlRef acl = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
//                                                                            kSecAttrAccessibleAlwaysThisDeviceOnly,
//                                                                            kSecAccessControlApplicationPassword, &error);
//
//            if (acl == NULL || error != NULL) {
//                NSString *errorString = [NSString stringWithFormat:@"can't create acl: %@", error];
//                reject(@"storage_error", errorString, nil);
//                return;
//            }
//
//            query[(__bridge id)kSecAttrAccessControl] = (__bridge_transfer id)acl;
        }
        else{
            
//            CFErrorRef error = NULL;
//            SecAccessControlRef acl = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
//                                                                            kSecAttrAccessibleAlwaysThisDeviceOnly,
//                                                                            kSecAccessControlBiometryCurrentSet, &error);
//
//            if (acl == NULL || error != NULL) {
//                NSString *errorString = [NSString stringWithFormat:@"can't create acl: %@", error];
//                reject(@"storage_error", errorString, nil);
//                return;
//            }
//
//            query[(__bridge id)kSecAttrAccessControl] = (__bridge_transfer id)acl;
        }
        
        query[(__bridge id)kSecUseAuthenticationContext] = validationContext;
        query[(id)kSecUseAuthenticationUI] = (id)kSecUseAuthenticationUIFail;
        query[(id)kSecUseOperationPrompt] = promptMessage;
        validationContext.localizedFallbackTitle = promptMessage;
//        [validationContext evaluatePolicy:kLAPolicyDeviceOwnerAuthentication localizedReason:promptMessage reply:^(BOOL success, NSError * _Nullable error) {
//            if (success) {
        
                SecKeyRef privateKey;
                OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKey);
                
                if (status == errSecSuccess) {
                    NSError *error;
                    NSData *dataToSign = [payload dataUsingEncoding:NSUTF8StringEncoding];
                    NSData *signature = CFBridgingRelease(SecKeyCreateSignature(privateKey, kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256, (CFDataRef)dataToSign, (void *)&error));
                    
                    if (signature != nil) {
                        NSString *signatureString = [signature base64EncodedStringWithOptions:0];
                        NSDictionary *result = @{
                            @"success": @(YES),
                            @"signature": signatureString
                        };
                        resolve(result);
                    } else if (error.code == errSecUserCanceled) {
                        NSDictionary *result = @{
                            @"success": @(NO),
                            @"error": @"User cancellation"
                        };
                        resolve(result);
                    } else {
                        NSString *message = [NSString stringWithFormat:@"Signature error: %@", error];
                        reject(@"signature_error", message, nil);
                    }
                } else if (status == errSecInteractionNotAllowed) {
                    NSDictionary *result = @{
                        @"success": @(NO),
                        @"error": @"Authentication failed"
                    };
                    resolve(result);
                }
                else {
                    NSString *message = [NSString stringWithFormat:@"Signature error: %@",[self keychainErrorToString:status]];
                    reject(@"signature_error", message, nil);
                }
//            } else {
//                reject(@"storage_error", @"Invalid application password", nil);
//            }
//        }];
        
    });
}

RCT_EXPORT_METHOD(simplePrompt: (NSDictionary *)params resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *promptMessage = [RCTConvert NSString:params[@"promptMessage"]];
        
        LAContext *context = [[LAContext alloc] init];
        context.localizedFallbackTitle = @"";
        
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:promptMessage reply:^(BOOL success, NSError *biometricError) {
            if (success) {
                NSDictionary *result = @{
                    @"success": @(YES)
                };
                resolve(result);
            } else if (biometricError.code == LAErrorUserCancel) {
                NSDictionary *result = @{
                    @"success": @(NO),
                    @"error": @"User cancellation"
                };
                resolve(result);
            } else {
                NSString *message = [NSString stringWithFormat:@"%@", biometricError];
                reject(@"biometric_error", message, nil);
            }
        }];
    });
}

RCT_EXPORT_METHOD(biometricKeysExist: (NSDictionary *)params resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *keyTag = [RCTConvert NSString:params[@"keyTag"]];
        BOOL biometricKeyExists = [self doesBiometricKeyExist:keyTag];
        
        if (biometricKeyExists) {
            NSDictionary *result = @{
                @"keysExist": @(YES)
            };
            resolve(result);
        } else {
            NSDictionary *result = @{
                @"keysExist": @(NO)
            };
            resolve(result);
        }
    });
}

- (NSData *) getBiometricKeyTag: (NSString *) differentiator {
    NSString *biometricKeyAlias = [NSString stringWithFormat:@"com.rnbiometrics.biometricKey.%@", differentiator];
    NSData *biometricKeyTag = [biometricKeyAlias dataUsingEncoding:NSUTF8StringEncoding];
    return biometricKeyTag;
}

- (BOOL) doesBiometricKeyExist: (NSString *) keyTag {
    NSData *biometricKeyTag = [self getBiometricKeyTag: keyTag];
    NSDictionary *searchQuery = @{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrApplicationTag: biometricKeyTag,
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
        (id)kSecUseAuthenticationUI: (id)kSecUseAuthenticationUIFail
    };
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)searchQuery, nil);
    return status == errSecSuccess || status == errSecInteractionNotAllowed;
}

-(OSStatus) deleteBiometricKey:(NSString *) keyTag {
    NSData *biometricKeyTag = [self getBiometricKeyTag:keyTag];
    NSDictionary *deleteQuery = @{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrApplicationTag: biometricKeyTag,
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA
    };

    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
    return status;
}

- (NSString *)getBiometryType:(LAContext *)context
{
    if (@available(iOS 11, *)) {
        return (context.biometryType == LABiometryTypeFaceID) ? @"FaceID" : @"TouchID";
    }

    return @"TouchID";
}

- (NSString *)keychainErrorToString:(OSStatus)error {
    NSString *message = [NSString stringWithFormat:@"%ld", (long)error];

    switch (error) {
        case errSecSuccess:
            message = @"success";
            break;

        case errSecDuplicateItem:
            message = @"error item already exists";
            break;

        case errSecItemNotFound :
            message = @"error item not found";
            break;

        case errSecAuthFailed:
            message = @"error item authentication failed";
            break;

        case errSecInteractionNotAllowed:
            message = @"error user interaction is not allowed";
            break;

        default:
            break;
    }

    return message;
}


- (NSData *)addHeaderPublickey:(NSData *)publicKeyData {

    unsigned char builder[15];
    NSMutableData * encKey = [[NSMutableData alloc] init];
    unsigned long bitstringEncLength;

    static const unsigned char _encodedRSAEncryptionOID[15] = {

        /* Sequence of length 0xd made up of OID followed by NULL */
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00

    };
    // When we get to the bitstring - how will we encode it?
    if  ([publicKeyData length ] + 1  < 128 )
        bitstringEncLength = 1 ;
    else
        bitstringEncLength = (([publicKeyData length ] +1 ) / 256 ) + 2 ;
    //
    //        // Overall we have a sequence of a certain length
    builder[0] = 0x30;    // ASN.1 encoding representing a SEQUENCE
    //        // Build up overall size made up of -
    //        // size of OID + size of bitstring encoding + size of actual key
    size_t i = sizeof(_encodedRSAEncryptionOID) + 2 + bitstringEncLength + [publicKeyData length];
    size_t j = encodeLength(&builder[1], i);
    [encKey appendBytes:builder length:j +1];

    // First part of the sequence is the OID
    [encKey appendBytes:_encodedRSAEncryptionOID
                 length:sizeof(_encodedRSAEncryptionOID)];

    // Now add the bitstring
    builder[0] = 0x03;
    j = encodeLength(&builder[1], [publicKeyData length] + 1);
    builder[j+1] = 0x00;
    [encKey appendBytes:builder length:j + 2];

    // Now the actual key
    [encKey appendData:publicKeyData];

    return encKey;
}

size_t encodeLength(unsigned char * buf, size_t length) {

    // encode length in ASN.1 DER format
    if (length < 128) {
        buf[0] = length;
        return 1;
    }

    size_t i = (length / 256) + 1;
    buf[0] = i + 0x80;
    for (size_t j = 0 ; j < i; ++j) {
        buf[i - j] = length & 0xFF;
        length = length >> 8;
    }

    return i + 1;
}

@end
