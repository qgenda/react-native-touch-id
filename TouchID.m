#import "TouchID.h"
#import <React/RCTUtils.h>
#import <LocalAuthentication/LocalAuthentication.h>

NSString *const kTouchIDBiometricAuthenticationTypeNone = @"None";
NSString *const kTouchIDBiometricAuthenticationTypeFingerprint = @"Fingerprint";
NSString *const kTouchIDBiometricAuthenticationTypeFacialRecognition = @"FacialRecognition";

@implementation TouchID

static LAContext *context;

RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(isSupported: (RCTResponseSenderBlock)callback)
{
    // Automatically invalidate any existing LAContext.  The previous callbacks will be called with error LAErrorAppCancel
    [context invalidate];

    context = [[LAContext alloc] init];
    NSError *error;

    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
        // Default the authentication type to TouchID for devices < iOS 11.0.  If TouchID is not supported or enrolled
        //   then canEvaluatePolicy will return false.
        NSString *biometricAuthenticationType = kTouchIDBiometricAuthenticationTypeFingerprint;

        if([context respondsToSelector:@selector(biometryType)]) {
            switch(context.biometryType) {
                case LABiometryTypeTouchID:
                    biometricAuthenticationType = kTouchIDBiometricAuthenticationTypeFingerprint;
                    break;
                case LABiometryTypeFaceID:
                    biometricAuthenticationType = kTouchIDBiometricAuthenticationTypeFacialRecognition;
                    break;
            }
        }

        callback(@[[NSNull null], @true, biometricAuthenticationType]);
        // Device does not support TouchID
    } else {
        callback(@[RCTMakeError(@"RCTTouchIDNotSupported", nil, nil)]);
        return;
    }
}

RCT_EXPORT_METHOD(authenticate: (NSString *)reason
                      callback: (RCTResponseSenderBlock)callback)
{
    // Automatically invalidate any existing LAContext.  The previous callbacks will be called with error LAErrorAppCancel
    [context invalidate];

    context = [[LAContext alloc] init];
    NSError *error;

    // Device has TouchID
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
        // Attempt Authentification
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                localizedReason:reason
                          reply:^(BOOL success, NSError *error)
         {
             // Failed Authentication
             if (error) {
                 NSString *errorReason;

                 switch (error.code) {
                     case LAErrorAuthenticationFailed:
                         errorReason = @"LAErrorAuthenticationFailed";
                         break;

                     case LAErrorUserCancel:
                         errorReason = @"LAErrorUserCancel";
                         break;

                     case LAErrorUserFallback:
                         errorReason = @"LAErrorUserFallback";
                         break;

                     case LAErrorSystemCancel:
                         errorReason = @"LAErrorSystemCancel";
                         break;

                     case LAErrorAppCancel:
                         errorReason = @"LAErrorAppCancel";
                         break;

                     case LAErrorPasscodeNotSet:
                         errorReason = @"LAErrorPasscodeNotSet";
                         break;

                     case LAErrorTouchIDNotAvailable:
                         errorReason = @"LAErrorTouchIDNotAvailable";
                         break;

                     case LAErrorTouchIDNotEnrolled:
                         errorReason = @"LAErrorTouchIDNotEnrolled";
                         break;

                     default:
                         errorReason = @"RCTTouchIDUnknownError";
                         break;
                 }

                 NSLog(@"Authentication failed: %@", errorReason);
                 callback(@[RCTMakeError(errorReason, nil, nil)]);
                 return;
             }

             // Authenticated Successfully
             callback(@[[NSNull null], @"Authenticat with Touch ID."]);
         }];

        // Device does not support TouchID
    } else {
        callback(@[RCTMakeError(@"RCTTouchIDNotSupported", nil, nil)]);
        return;
    }
}

RCT_EXPORT_METHOD(cancelAuthentication: (RCTResponseSenderBlock)callback)
{
    [context invalidate];
    callback(@[[NSNull null]]);
}

@end
