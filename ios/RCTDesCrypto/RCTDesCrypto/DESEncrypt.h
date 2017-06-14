//
//  DESEncrypt.h
//  DESEncrypt For Iphone
//
//  Created by Alur on 11-12-22.
//  Copyright (c) 2011年 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>

#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

#define kDESKeySize				kCCKeySizeDES
#define kDESBlockSize	        kCCBlockSizeDES

#define TEST_DES_KEY @"405E2540212A2828"
#define TEST_STRINGS @"中国",nil
#define TEST_DES_ENCRYPTED @"6751575DDE189B45C6A40FF5E95D95094B2CFF4C05D3C0AD628ABD6A8DE17C3FCDA6416FF4ED39613705359FE16377C2D7D4FD5EFB499122EA655E54F67923104346FE7049945770",nil

typedef enum {
    AlgorithmDES = 2
} EncryptAlgorithm;

@interface DESEncrypt : NSObject {
	NSData *publicKeyData;
	NSData *privateKeyData;
	NSData *symmetricKeyData;
	
	bool   isImportKey;
}

@property(nonatomic, retain)    NSData *publicKeyData;
@property(nonatomic, retain)    NSData *privateKeyData;
@property(nonatomic, retain)    NSData *symmetricKeyData;

@property(nonatomic, readwrite) bool isImportKey;


/*
 @//加密
 @ deskey 密钥
 @ stringToEncrypt 用于加密的明文
 @ 返回 加密后的字符串
 */
- (NSString*) DESEncryptionByKey:(NSString *)deskey StringToEncrypt:(NSString *)stringToEncrypt;


/*
 @//解密
 @ deskey 密钥 
 @ encryptedString 用于解密的密文
 @ 返回 解密后的字符串
 */
- (NSString*) DESJavaEncryptionByKey:(NSString *)deskey EncryptedString:(NSString *) encryptedString;


@end

