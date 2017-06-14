//
//  DESEncrypt.m
//  MobileApprove
//
//  Created by Alur on 11-12-22.
//  Copyright (c) 2011年 __MyCompanyName__. All rights reserved.
//

#import "DESEncrypt.h"

@interface DESEncrypt()

- (NSData*) decrypt:(NSData *)plainText Algorithm:(EncryptAlgorithm)alg key:(NSData *)aSymmetricKey padding:(CCOptions *)pkcs7;
- (NSData*) encrypt:(NSData *)plainText Algorithm:(EncryptAlgorithm)alg key:(NSData *)aSymmetricKey padding:(CCOptions *)pkcs7;
- (NSData*) doCipherDES:(NSData *)plainText key:(NSData *)aSymmetricKey context:(CCOperation)encryptOrDecrypt padding:(CCOptions *)pkcs7;
- (NSString*) getPublicKeyString;
- (NSString*) getPrivateKeyString;
- (NSString*) getSymmetricKeyString;
- (NSData*) getSymmetricKeyFromRandomString:(NSString*)strKey;
- (NSData*) getSymmetricKeyFromString:(NSString*)strKey;
- (NSData*) hexToBytes:(NSString*)strHex;
- (NSString *)hexvalStringWithData:(NSData *)data;

@end

@implementation DESEncrypt

@synthesize publicKeyData;
@synthesize privateKeyData;
@synthesize symmetricKeyData;

@synthesize isImportKey;

CCOptions encryptPadding = kCCOptionPKCS7Padding;


- (NSData*) getSymmetricKeyFromString:(NSString*)strKey{
	isImportKey = YES;
	return [self hexToBytes:strKey];
	//return [strKey dataUsingEncoding:NSASCIIStringEncoding];
}

- (NSData*) getSymmetricKeyFromRandomString:(NSString*)strKey{
	return [strKey dataUsingEncoding:NSASCIIStringEncoding];
}

- (NSString*) getSymmetricKeyString{
	if (isImportKey) {
		//return [[[NSString alloc] initWithData:symmetricKeyData encoding:NSUTF8StringEncoding] autorelease];
		return[[NSString alloc] initWithData:symmetricKeyData encoding:NSASCIIStringEncoding] ;
	}
	else {
		//return [symmetricKeyData hexval];
        return [self hexvalStringWithData:symmetricKeyData];
	}
}

- (NSString*) getPublicKeyString{
	NSString *strKey = [[NSString alloc] initWithData:publicKeyData encoding:NSASCIIStringEncoding];
	return strKey;
	//return [publicKeyData encodeBase64];
}

- (NSString*) getPrivateKeyString{
	NSString *strKey = [[NSString alloc] initWithData:privateKeyData encoding:NSASCIIStringEncoding];
	return strKey;
	//return [privateKeyData encodeBase64];
}

- (NSData*) doCipherDES:(NSData *)plainText key:(NSData *)aSymmetricKey
				context:(CCOperation)encryptOrDecrypt padding:(CCOptions *)pkcs7 
{
    CCCryptorStatus ccStatus = kCCSuccess;
    // Symmetric crypto reference.
    CCCryptorRef thisEncipher = NULL;
    // Cipher Text container.
    NSData * cipherOrPlainText = nil;
    // Pointer to output buffer.
    uint8_t * bufferPtr = NULL;
    // Total size of the buffer.
    size_t bufferPtrSize = 0;
    // Remaining bytes to be performed on.
    size_t remainingBytes = 0;
    // Number of bytes moved to buffer.
    size_t movedBytes = 0;
    // Length of plainText buffer.
    size_t plainTextBufferSize = 0;
    // Placeholder for total written.
    size_t totalBytesWritten = 0;
    // A friendly helper pointer.
    uint8_t * ptr;
	
    // Initialization vector; dummy in this case 0's.
    uint8_t iv[kDESBlockSize];
    memset((void *) iv, 0x0, (size_t) sizeof(iv));
	
    //NSLog(@"doCipher DES: plaintext: %@", plainText);
    //NSLog(@"doCipher DES: key length: %d", [aSymmetricKey length]);
	
    //LOGGING_FACILITY(plainText != nil, @"PlainText object cannot be nil." );
    //LOGGING_FACILITY(aSymmetricKey != nil, @"Symmetric key object cannot be nil." );
    //LOGGING_FACILITY(pkcs7 != NULL, @"CCOptions * pkcs7 cannot be NULL." );
    //LOGGING_FACILITY([aSymmetricKey length] == kChosenCipherKeySize, @"Disjoint choices for key size." );
	
    plainTextBufferSize = [plainText length];
	
    //LOGGING_FACILITY(plainTextBufferSize > 0, @"Empty plaintext passed in." );
	
    //NSLog(@"DES pkcs7: %d", *pkcs7);
    // We don't want to toss padding on if we don't need to
    if(encryptOrDecrypt == kCCEncrypt) {
        if(*pkcs7 != kCCOptionECBMode) {
            if((plainTextBufferSize % kDESBlockSize) == 0) {
                //*pkcs7 = 0x0000;
                *pkcs7 = kCCOptionPKCS7Padding;
            } else {
                *pkcs7 = kCCOptionPKCS7Padding;
            }
        }
    } else if(encryptOrDecrypt != kCCDecrypt) {
        NSLog(@"Invalid CCOperation parameter [%d] for cipher DES context.", *pkcs7 );
    } 
	
    // Create and Initialize the crypto reference.
    ccStatus = CCCryptorCreate(encryptOrDecrypt,
                               kCCAlgorithmDES,
                               *pkcs7 + kCCOptionECBMode,
                               (const void *)[aSymmetricKey bytes],
                               kDESKeySize,
                               (const void *)iv,
                               &thisEncipher
                               );
	
	//LOGGING_FACILITY1( ccStatus == kCCSuccess, @"Problem creating the context, ccStatus == %d.", ccStatus );
	//NSLog(@"ccStatus:%d",ccStatus);
    // Calculate byte block alignment for all calls through to and including final.
    bufferPtrSize = CCCryptorGetOutputLength(thisEncipher, plainTextBufferSize, true);
	
    // Allocate buffer.
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t) );
	
    // Zero out buffer.
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
	
    // Initialize some necessary book keeping.
	
    ptr = bufferPtr;
	
    // Set up initial size.
    remainingBytes = bufferPtrSize;
	
    // Actually perform the encryption or decryption.
    ccStatus = CCCryptorUpdate(thisEncipher,
                               (const void *) [plainText bytes],
                               plainTextBufferSize,
                               ptr,
                               remainingBytes,
                               &movedBytes
                               );
	//NSLog(@"ccStatus:%d",ccStatus);
	//LOGGING_FACILITY1( ccStatus == kCCSuccess, @"Problem with CCCryptorUpdate, ccStatus == %d.", ccStatus );
	
    // Handle book keeping.
    ptr += movedBytes;
    remainingBytes -= movedBytes;
    totalBytesWritten += movedBytes;
	
    // Finalize everything to the output buffer.
    ccStatus = CCCryptorFinal(thisEncipher,
                              ptr,
                              remainingBytes,
                              &movedBytes
                              );
//	NSLog(@"ccStatus:%d",ccStatus);
    totalBytesWritten += movedBytes;
	
    if(thisEncipher) {
        (void) CCCryptorRelease(thisEncipher);
        thisEncipher = NULL;
    }
	
    //LOGGING_FACILITY1( ccStatus == kCCSuccess, @"Problem with encipherment ccStatus == %d", ccStatus );
	
    if (ccStatus == kCCSuccess)
        cipherOrPlainText = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)totalBytesWritten];
    else
        cipherOrPlainText = nil;
	
    if(bufferPtr) free(bufferPtr);
	
    return cipherOrPlainText;
}

- (NSData*) encrypt:(NSData *)plainText Algorithm:(EncryptAlgorithm)alg key:(NSData *)aSymmetricKey padding:(CCOptions *)pkcs7
{
    return [self doCipherDES:plainText key:aSymmetricKey context:kCCEncrypt padding:pkcs7];
}

- (NSData*) decrypt:(NSData *)plainText Algorithm:(EncryptAlgorithm)alg key:(NSData *)aSymmetricKey padding:(CCOptions *)pkcs7
{
    return [self doCipherDES:plainText key:aSymmetricKey context:kCCDecrypt padding:pkcs7];
    
}

- (NSString*) DESEncryptionByKey:(NSString *)deskey StringToEncrypt:(NSString *)stringToEncrypt{
	NSString *resultString;
    
	[self setSymmetricKeyData:[self getSymmetricKeyFromString:deskey]];
    
    
    NSData *encryptedData = [self encrypt:[stringToEncrypt dataUsingEncoding:NSUTF8StringEncoding] 
                                Algorithm:AlgorithmDES key:symmetricKeyData padding:&encryptPadding];
    
    resultString = [self hexvalStringWithData:encryptedData];
    
	return resultString;
}

- (NSString*) DESJavaEncryptionByKey:(NSString *)deskey EncryptedString:(NSString *) encryptedString{
	NSString *resultString;
	
	[self setSymmetricKeyData:[self getSymmetricKeyFromString:deskey]];
    NSData *encryptedData = [self hexToBytes:encryptedString];
    
    NSData *decryptData = [self decrypt:encryptedData Algorithm:AlgorithmDES key:symmetricKeyData padding:&encryptPadding];
    
    NSString *tempString = [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding];
    
    resultString = tempString;
    
	return resultString;
}

- (NSData*) hexToBytes:(NSString*)strHex {
	NSMutableData* data = [[NSMutableData alloc] init];
	int idx;
	for (idx = 0; idx+2 <= strHex.length; idx+=2) {
		NSRange range = NSMakeRange(idx, 2);
		NSString* hexStr = [strHex substringWithRange:range];
		NSScanner* scanner = [NSScanner scannerWithString:hexStr];
		unsigned int intValue;
		[scanner scanHexInt:&intValue];
		[data appendBytes:&intValue length:1];
	}
	return data;
}
- (NSString *)hexvalStringWithData:(NSData *)data 
{
    NSMutableString *hex = [NSMutableString string];
    unsigned char *bytes = (unsigned char *)[data bytes];
    char temp[3];
    int i = 0;
    
    for (i = 0; i < [data length]; i++) {
        temp[0] = temp[1] = temp[2] = 0;
        (void)sprintf(temp, "%02x", bytes[i]);
        [hex appendString:[NSString stringWithUTF8String:temp]];
    }
    
    return hex;
}

@end
