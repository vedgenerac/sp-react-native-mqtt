///
//  Mqtt.m
//  RCTMqtt
//
//  Created by Tuan PM on 2/13/16.
//  Copyright © 2016 Tuan PM. All rights reserved.
//  Updated by NaviOcean on 01/04/18
//  Updated by Scott Spitler of KUHMUTE on 03/01/2021.
//  Copyright © 2021 Scott Spitler. All rights reserved.
//

#import "Mqtt.h"
#import <React/RCTEventEmitter.h>

#include <stdio.h>
#include <stdlib.h>

@interface Mqtt ()

@property (strong, nonatomic) MQTTSessionManager *manager;
@property (nonatomic, strong) NSDictionary *defaultOptions;
@property (nonatomic, retain) NSMutableDictionary *options;
@property (nonatomic, strong) NSString *clientRef;
@property (nonatomic, strong) RCTEventEmitter * emitter;

@end

@implementation Mqtt


- (id)init {
    if ((self = [super init])) {
        self.defaultOptions = @{
            @"host": @"localhost",
            @"port": @1883,
            @"protocol": @"tcp", // ws
            @"tls": @NO,
            @"keepalive": @120, // second
            @"clientId": @"react-native-mqtt",
            @"protocolLevel": @4,
            @"clean": @YES,
            @"auth": @NO,
            @"user": @"",
            @"pass": @"",
            @"will": @NO,
            @"willMsg": [NSNull null],
            @"willtopic": @"",
            @"willQos": @0,
            @"willRetainFlag": @NO,
            // New options for mTLS
            @"clientCertPath": [NSNull null], // Path to .p12 file
            @"clientCertPassword": [NSNull null], // Password for .p12 file
            // New option for root CA
            @"rootCAPath": [NSNull null] // Path to root CA .cer or .pem file
        };
    }
    return self;
}

- (instancetype)initWithEmitter:(RCTEventEmitter *)emitter
                        options:(NSDictionary *)options
                      clientRef:(NSString *)clientRef {
    self = [self init];
    self.emitter = emitter;
    self.clientRef = clientRef;
    self.options = [NSMutableDictionary dictionaryWithDictionary:self.defaultOptions];
    for (NSString *key in options.keyEnumerator) {
        [self.options setValue:options[key] forKey:key];
    }
    return self;
}

// Helper method to load client certificate from a .p12 file
- (NSArray *)loadCertificatesFromP12:(NSString *)certPath password:(NSString *)password {
    if (!certPath || [certPath isEqual:[NSNull null]] || !password || [password isEqual:[NSNull null]]) {
        return nil;
    }

    NSData *p12Data = [NSData dataWithContentsOfFile:certPath];
    if (!p12Data) {
        NSLog(@"Failed to load certificate file at path: %@", certPath);
        return nil;
    }

    CFStringRef passwordRef = (__bridge CFStringRef)password;
    const void *keys[] = {kSecImportExportPassphrase};
    const void *values[] = {passwordRef};
    CFDictionaryRef optionsDict = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    CFArrayRef items = NULL;

    OSStatus status = SecPKCS12Import((__bridge CFDataRef)p12Data, optionsDict, &items);
    CFRelease(optionsDict);

    if (status != errSecSuccess || !items) {
        NSLog(@"Failed to import PKCS12 data: %d", (int)status);
        return nil;
    }

    CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
    SecIdentityRef identity = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
    if (!identity) {
        CFRelease(items);
        return nil;
    }

    SecCertificateRef certificate = NULL;
    status = SecIdentityCopyCertificate(identity, &certificate);
    if (status != errSecSuccess || !certificate) {
        CFRelease(items);
        return nil;
    }

    NSArray *certificates = @[(__bridge id)identity, (__bridge id)certificate];
    CFRelease(certificate);
    CFRelease(items);

    return certificates;
}

// Helper method to load root CA certificate from a file
- (SecCertificateRef)loadRootCACertificateFromPath:(NSString *)rootCAPath {
    if (!rootCAPath || [rootCAPath isEqual:[NSNull null]]) {
        return NULL;
    }

    NSData *rootCAData = [NSData dataWithContentsOfFile:rootCAPath];
    if (!rootCAData) {
        NSLog(@"Failed to load root CA file at path: %@", rootCAPath);
        return NULL;
    }

    SecCertificateRef rootCACert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)rootCAData);
    if (!rootCACert) {
        NSLog(@"Failed to create SecCertificateRef from root CA data");
    }

    return rootCACert;
}

- (void)connect {
    MQTTSSLSecurityPolicy *securityPolicy = nil;
    NSArray *certificates = nil;

    if ([self.options[@"tls"] boolValue]) {
        // Initialize security policy
        securityPolicy = [MQTTSSLSecurityPolicy policyWithPinningMode:MQTTSSLPinningModeNone];
        securityPolicy.allowInvalidCertificates = YES; // Set to NO in production for strict validation

        // Load root CA certificate for server certificate validation
        NSString *rootCAPath = self.options[@"rootCAPath"];
        SecCertificateRef rootCACert = [self loadRootCACertificateFromPath:rootCAPath];
        if (rootCACert) {
            securityPolicy.pinnedCertificates = @[(__bridge id)rootCACert];
            securityPolicy.validatesCertificateChain = YES; // Enable chain validation with root CA
            CFRelease(rootCACert); // Release after adding to array
        }

        // Load client certificate for mTLS (if provided)
        NSString *certPath = self.options[@"clientCertPath"];
        NSString *certPassword = self.options[@"clientCertPassword"];
        certificates = [self loadCertificatesFromP12:certPath password:certPassword];
    }

    NSData *willMsg = nil;
    if (self.options[@"willMsg"] != [NSNull null]) {
        willMsg = [self.options[@"willMsg"] dataUsingEncoding:NSUTF8StringEncoding];
    }

    if (!self.manager) {
        dispatch_queue_t queue = dispatch_queue_create("com.hawking.app.anchor.mqtt", NULL);
        
        self.manager = [[MQTTSessionManager alloc] initWithPersistence:NO
                                                        maxWindowSize:MQTT_MAX_WINDOW_SIZE
                                                          maxMessages:MQTT_MAX_MESSAGES
                                                              maxSize:MQTT_MAX_SIZE
                                           maxConnectionRetryInterval:60.0
                                                  connectInForeground:NO
                                                       streamSSLLevel:nil
                                                                queue:queue];
        self.manager.delegate = self;

        MQTTCFSocketTransport *transport = [[MQTTCFSocketTransport alloc] init];
        transport.host = [self.options valueForKey:@"host"];
        transport.port = [self.options[@"port"] intValue];
        transport.voip = YES;
        self.manager.session.transport = transport;

        [self.manager connectTo:[self.options valueForKey:@"host"]
                           port:[self.options[@"port"] intValue]
                            tls:[self.options[@"tls"] boolValue]
                      keepalive:[self.options[@"keepalive"] intValue]
                          clean:[self.options[@"clean"] intValue]
                           auth:[self.options[@"auth"] boolValue]
                           user:[self.options valueForKey:@"user"]
                           pass:[self.options valueForKey:@"pass"]
                           will:[self.options[@"will"] boolValue]
                      willTopic:[self.options valueForKey:@"willTopic"]
                        willMsg:willMsg
                        willQos:(MQTTQosLevel)[self.options[@"willQos"] intValue]
                 willRetainFlag:[self.options[@"willRetainFlag"] boolValue]
                   withClientId:[self.options valueForKey:@"clientId"]
                 securityPolicy:securityPolicy
                   certificates:certificates
                  protocolLevel:MQTTProtocolVersion311
                 connectHandler:^(NSError *error) {
                     if (error) {
                         [self.emitter sendEventWithName:@"mqtt_events"
                                                    body:@{@"event": @"error",
                                                           @"clientRef": self.clientRef,
                                                           @"message": [error localizedDescription]}];
                     }
                 }];
    } else {
        [self.manager connectToLast:^(NSError *error) {
            if (error) {
                [self.emitter sendEventWithName:@"mqtt_events"
                                           body:@{@"event": @"error",
                                                  @"clientRef": self.clientRef,
                                                  @"message": [error localizedDescription]}];
            }
        }];
    }
}

- (void)sessionManager:(MQTTSessionManager *)sessonManager didChangeState:(MQTTSessionManagerState)newState {
    switch (newState) {
            
        case MQTTSessionManagerStateClosed:
            [self.emitter sendEventWithName:@"mqtt_events"
                                       body:@{@"event": @"closed",
                                              @"clientRef": self.clientRef,
                                              @"message": @"closed"
                                              }];
            break;
        case MQTTSessionManagerStateClosing:
            [self.emitter sendEventWithName:@"mqtt_events"
                                       body:@{@"event": @"closing",
                                              @"clientRef": self.clientRef,
                                              @"message": @"closing"
                                              }];
            break;
        case MQTTSessionManagerStateConnected:
            [self.emitter sendEventWithName:@"mqtt_events"
                                       body:@{@"event": @"connect",
                                              @"clientRef": self.clientRef,
                                              @"message": @"connected"
                                              }];
            break;
        case MQTTSessionManagerStateConnecting:
            [self.emitter sendEventWithName:@"mqtt_events"
                                       body:@{@"event": @"connecting",
                                              @"clientRef": self.clientRef,
                                              @"message": @"connecting"
                                              }];
            break;
        case MQTTSessionManagerStateError: {
            NSError *lastError = self.manager.lastErrorCode;
            NSString *errorMsg = [NSString stringWithFormat:@"error: %@", [lastError localizedDescription]];
            [self.emitter sendEventWithName:@"mqtt_events"
                                       body:@{@"event": @"error",
                                              @"clientRef": self.clientRef,
                                              @"message": errorMsg
                                              }];
            break;
        }
        case MQTTSessionManagerStateStarting:
        default:
            break;
    }
}

- (void)messageDelivered:(UInt16)msgID {
    NSLog(@"messageDelivered");
    NSString *codeString = [NSString stringWithFormat:@"%d",msgID];
    [self.emitter sendEventWithName:@"mqtt_events"
                               body:@{@"event": @"msgSent",
                                      @"clientRef": self.clientRef,
                                      @"message": codeString
                                      }];
}

- (void) disconnect {
    // [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:1.0]];
    [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:1.0]];
    [self.manager disconnectWithDisconnectHandler:^(NSError *error) {
    }];
    
}

- (BOOL) isConnected {
    //NSLog(@"Trying to check for connection...");
    if(self.manager.session.status == MQTTSessionStatusConnected) {
        return true;
    }
    return false;
}

- (BOOL) isSubbed:(NSString *)topic {
    //NSLog(@"Checking to see if listening to topic... %@", topic);
    if([self.manager.subscriptions objectForKey:topic]) {
        return true;
    }
    return false;
}
/*
    Returns array of objects with keys:
        -topic: type string
        -qos  : type int

    TODO:
        Allocate all space before hand, remove "tmp" holding variable.
        Still learning Objective C...
*/

- (NSMutableArray *) getTopics {
    //NSLog(@"Trying to pull all connected topics....");
    NSMutableArray * ret;
    int i = 0;
    for(id key in self.manager.subscriptions) {
        id keySet = [NSDictionary sharedKeySetForKeys:@[@"topic", @"qos"]];
        NSMutableDictionary *tmp = [NSMutableDictionary dictionaryWithSharedKeySet:keySet];
        tmp[@"topic"] = key;
        tmp[@"qos"] = [self.manager.subscriptions objectForKey:key];
        ret[i] = tmp;
        i++;
    }
    return ret;
}

- (void) subscribe:(NSString *)topic qos:(NSNumber *)qos {
    NSMutableDictionary *subscriptions = [self.manager.subscriptions mutableCopy];
    [subscriptions setObject:qos forKey: topic];
    [self.manager setSubscriptions:subscriptions];
}

- (void) unsubscribe:(NSString *)topic {
    NSMutableDictionary *subscriptions = [self.manager.subscriptions mutableCopy];
    [subscriptions removeObjectForKey: topic];
    [self.manager setSubscriptions:subscriptions];
}

- (void) publish:(NSString *) topic data:(NSData *)data qos:(NSNumber *)qos retain:(BOOL) retain {
    [self.manager sendData:data topic:topic qos:[qos intValue] retain:retain];
}

- (void)handleMessage:(NSData *)data onTopic:(NSString *)topic retained:(BOOL)retained {
    NSString *dataString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    [self.emitter sendEventWithName:@"mqtt_events"
                               body:@{
                                      @"event": @"message",
                                      @"clientRef": self.clientRef,
                                      @"message": @{
                                              @"topic": topic,
                                              @"data": dataString,
                                              @"retain": [NSNumber numberWithBool:retained]
                                              }
                                      }];
    
}


- (void)dealloc
{
    [self disconnect];
}

@end
