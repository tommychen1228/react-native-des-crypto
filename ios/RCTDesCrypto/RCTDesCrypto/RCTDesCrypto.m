//
//  RCTDes.m
//  RCTDes
//
//  Created by fangyunjiang on 15/11/4.
//  Copyright (c) 2015年 remobile. All rights reserved.
//


#import "RCTDesCrypto.h"
#import "DESEncrypt.h"

@implementation RCTDesCrypto
RCT_EXPORT_MODULE()

RCT_EXPORT_METHOD(decrypt:(NSString *)data key:(NSString *)key success:(RCTResponseSenderBlock)success error:(RCTResponseSenderBlock)error) {
    
    DESEncrypt *desEncrypt =  [[DESEncrypt alloc] init];
    NSString *str =  [desEncrypt DESJavaEncryptionByKey:@"365E2928392D7033"  EncryptedString:data];
    
    if (str == nil) {
        error(@[]);
    } else {
        success(@[str]);
    }
}
@end
