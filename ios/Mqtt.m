//
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

@interface Mqtt ()

@property (strong, nonatomic) MQTTSessionManager *manager;
@property (nonatomic, strong) NSDictionary *defaultOptions;
@property (nonatomic, retain) NSMutableDictionary *options;
@property (nonatomic, strong) NSString *clientRef;
@property (nonatomic, strong) RCTEventEmitter *emitter;

@end

@implementation Mqtt

- (id)init {
    if ((self = [super init])) {
        self.defaultOptions = @{
            @"host": @"localhost",
            @"port": @1883,
            @"protocol": @"tcp",
            @"tls": @NO,
            @"keepalive": @120,
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
            @"clientCertFile": [NSNull null], // e.g., "client-cert.pem"
            @"clientKeyFile": [NSNull null],  // e.g., "client-key.pem"
            @"rootCAFile": [NSNull null]      // e.g., "root-ca.pem"
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

// Helper method to convert PEM to DER with robust parsing
- (NSData *)derDataFromPem:(NSString *)pemString {
    if (!pemString || pemString.length == 0) {
        NSLog(@"PEM string is empty or nil");
        return nil;
    }

    // Log the full PEM content for debugging
    NSLog(@"Full PEM content (length: %lu): %@", (unsigned long)pemString.length, pemString);

    // Normalize line endings and remove extra whitespace
    NSString *normalizedPem = [pemString stringByReplacingOccurrencesOfString:@"\r\n" withString:@"\n"];
    normalizedPem = [normalizedPem stringByReplacingOccurrencesOfString:@"\r" withString:@"\n"];
    
    // Split into lines and extract base64 content
    NSArray *lines = [normalizedPem componentsSeparatedByString:@"\n"];
    NSMutableString *base64String = [NSMutableString string];
    BOOL inCertificate = NO;

    for (NSString *line in lines) {
        NSString *trimmedLine = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (trimmedLine.length == 0) continue;

        if ([trimmedLine isEqualToString:@"-----BEGIN CERTIFICATE-----"]) {
            inCertificate = YES;
            NSLog(@"Found BEGIN CERTIFICATE marker");
            continue;
        } else if ([trimmedLine isEqualToString:@"-----END CERTIFICATE-----"]) {
            inCertificate = NO;
            NSLog(@"Found END CERTIFICATE marker");
            break;
        } else if (inCertificate) {
            [base64String appendString:trimmedLine];
        }
    }

    if (base64String.length == 0) {
        NSLog(@"No valid base64 data extracted from PEM string");
        return nil;
    }

    NSLog(@"Extracted base64 content (length: %lu): %@", (unsigned long)base64String.length, base64String);

    // Decode base64 to DER
    NSData *derData = [[NSData alloc] initWithBase64EncodedString:base64String options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (!derData) {
        NSLog(@"Failed to decode base64 data to DER: %@", base64String);
        // Test if the base64 is valid
        NSData *testDecode = [[NSData alloc] initWithBase64EncodedString:base64String options:0];
        NSLog(@"Base64 decode test (strict): %@", testDecode ? @"Success" : @"Failed");
    } else {
        NSLog(@"Successfully converted PEM to DER, length: %lu", (unsigned long)derData.length);
    }
    return derData;
}

// Helper method to load client certificate and key from PEM files (placeholder)
- (NSArray *)loadCertificatesFromPemFiles {
    NSString *clientCertFile = self.options[@"clientCertFile"];
    NSString *clientKeyFile = self.options[@"clientKeyFile"];
    if (!clientCertFile || [clientCertFile isEqual:[NSNull null]] ||
        !clientKeyFile || [clientKeyFile isEqual:[NSNull null]]) {
        NSLog(@"Client certificate or key file not provided");
        return nil;
    }

    NSString *certPath = [[NSBundle mainBundle] pathForResource:[clientCertFile stringByDeletingPathExtension] ofType:[clientCertFile pathExtension] ?: @"HPV"];
    if (!certPath) {
        NSLog(@"Client certificate file not found: %@", clientCertFile);
        return nil;
    }
    NSString *certPem = [NSString stringWithContentsOfFile:certPath encoding:NSUTF8StringEncoding error:nil];
    if (!certPem) {
        NSLog(@"Failed to read client certificate file: %@", certPath);
        return nil;
    }
    NSData *certData = [self derDataFromPem:certPem];
    if (!certData) {
        NSLog(@"Failed to convert client certificate PEM to DER");
        return nil;
    }
    SecCertificateRef clientCert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certData);
    if (!clientCert) {
        NSLog(@"Failed to create SecCertificateRef from client certificate");
        return nil;
    }

    // Placeholder: Actual key loading requires PKCS12 conversion
    NSLog(@"WARNING: Client key loading not implemented; use a .p12 file instead");
    CFRelease(clientCert);
    return nil;
}

// Helper method to load root CA certificate from the main bundle
- (SecCertificateRef)loadRootCACertificateFromBundle {
    NSString *rootCAFile = self.options[@"rootCAFile"];
    if (!rootCAFile || [rootCAFile isEqual:[NSNull null]]) {
        NSLog(@"Root CA file name not provided in options");
        return NULL;
    }

    NSString *fileName = [rootCAFile stringByDeletingPathExtension];
    NSString *fileExtension = [rootCAFile pathExtension] ?: @"pem";
    NSString *rootCAPath = [[NSBundle mainBundle] pathForResource:fileName ofType:fileExtension];
    if (!rootCAPath) {
        NSLog(@"Root CA file not found in main bundle: %@.%@", fileName, fileExtension);
        NSArray *bundleContents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:[[NSBundle mainBundle] bundlePath] error:nil];
        NSLog(@"Bundle contents: %@", bundleContents);
        return NULL;
    } else {
        NSLog(@"Root CA file found at path: %@", rootCAPath);
    }

    NSError *error = nil;
    NSString *rootCAPem = [NSString stringWithContentsOfFile:rootCAPath encoding:NSUTF8StringEncoding error:&error];
    if (!rootCAPem || error) {
        NSLog(@"Failed to read root CA file at path %@: %@", rootCAPath, error.localizedDescription);
        return NULL;
    } else {
        NSLog(@"Root CA PEM content loaded, length: %lu", (unsigned long)rootCAPem.length);
    }

    // Try PEM conversion first
    NSData *rootCAData = [self derDataFromPem:rootCAPem];
    SecCertificateRef rootCACert = NULL;

    if (rootCAData) {
        rootCACert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)rootCAData);
        if (!rootCACert) {
            NSLog(@"Failed to create SecCertificateRef from converted PEM data. DER length: %lu", (unsigned long)rootCAData.length);
        } else {
            NSLog(@"Successfully created SecCertificateRef from PEM-converted DER");
            return rootCACert;
        }
    }

    // Fallback: Try loading as raw DER if PEM conversion fails
    NSLog(@"PEM conversion failed; attempting to load as raw DER");
    rootCAData = [NSData dataWithContentsOfFile:rootCAPath];
    if (rootCAData) {
        rootCACert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)rootCAData);
        if (!rootCACert) {
            NSLog(@"Failed to create SecCertificateRef from raw DER data. Length: %lu", (unsigned long)rootCAData.length);
        } else {
            NSLog(@"Successfully created SecCertificateRef from raw DER");
        }
    } else {
        NSLog(@"Failed to load raw DER data from file");
    }

    return rootCACert;
}

- (void)connect {
    MQTTSSLSecurityPolicy *securityPolicy = nil;
    NSArray *certificates = nil;

    if ([self.options[@"tls"] boolValue]) {
        securityPolicy = [MQTTSSLSecurityPolicy policyWithPinningMode:MQTTSSLPinningModeNone];
        securityPolicy.allowInvalidCertificates = YES; // Set to NO in production

        // Load root CA certificate
        SecCertificateRef rootCACert = [self loadRootCACertificateFromBundle];
        if (rootCACert) {
            securityPolicy.pinnedCertificates = @[(__bridge id)rootCACert];
            securityPolicy.validatesCertificateChain = YES;
            CFRelease(rootCACert);
        } else {
            NSLog(@"Root CA certificate loading failed; proceeding without custom CA");
        }

        // Load client certificate and key for mTLS
        certificates = [self loadCertificatesFromPemFiles];
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

- (void)sessionManager:(MQTTSessionManager *)sessionManager didChangeState:(MQTTSessionManagerState)newState {
    switch (newState) {
        case MQTTSessionManagerStateClosed:
            [self.emitter sendEventWithName:@"mqtt_events"
                                       body:@{@"event": @"closed",
                                              @"clientRef": self.clientRef,
                                              @"message": @"closed"}];
            break;
        case MQTTSessionManagerStateClosing:
            [self.emitter sendEventWithName:@"mqtt_events"
                                       body:@{@"event": @"closing",
                                              @"clientRef": self.clientRef,
                                              @"message": @"closing"}];
            break;
        case MQTTSessionManagerStateConnected:
            [self.emitter sendEventWithName:@"mqtt_events"
                                       body:@{@"event": @"connect",
                                              @"clientRef": self.clientRef,
                                              @"message": @"connected"}];
            break;
        case MQTTSessionManagerStateConnecting:
            [self.emitter sendEventWithName:@"mqtt_events"
                                       body:@{@"event": @"connecting",
                                              @"clientRef": self.clientRef,
                                              @"message": @"connecting"}];
            break;
        case MQTTSessionManagerStateError: {
            NSError *lastError = self.manager.lastErrorCode;
            NSString *errorMsg = [NSString stringWithFormat:@"error: %@", [lastError localizedDescription]];
            [self.emitter sendEventWithName:@"mqtt_events"
                                       body:@{@"event": @"error",
                                              @"clientRef": self.clientRef,
                                              @"message": errorMsg}];
            break;
        }
        case MQTTSessionManagerStateStarting:
        default:
            break;
    }
}

- (void)messageDelivered:(UInt16)msgID {
    NSLog(@"messageDelivered");
    NSString *codeString = [NSString stringWithFormat:@"%d", msgID];
    [self.emitter sendEventWithName:@"mqtt_events"
                               body:@{@"event": @"msgSent",
                                      @"clientRef": self.clientRef,
                                      @"message": codeString}];
}

- (void)disconnect {
    [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:1.0]];
    [self.manager disconnectWithDisconnectHandler:^(NSError *error) {
    }];
}

- (BOOL)isConnected {
    if (self.manager.session.status == MQTTSessionStatusConnected) {
        return true;
    }
    return false;
}

- (BOOL)isSubbed:(NSString *)topic {
    if ([self.manager.subscriptions objectForKey:topic]) {
        return true;
    }
    return false;
}

- (NSMutableArray *)getTopics {
    NSMutableArray *ret = [NSMutableArray array];
    for (id key in self.manager.subscriptions) {
        id keySet = [NSDictionary sharedKeySetForKeys:@[@"topic", @"qos"]];
        NSMutableDictionary *tmp = [NSMutableDictionary dictionaryWithSharedKeySet:keySet];
        tmp[@"topic"] = key;
        tmp[@"qos"] = [self.manager.subscriptions objectForKey:key];
        [ret addObject:tmp];
    }
    return ret;
}

- (void)subscribe:(NSString *)topic qos:(NSNumber *)qos {
    NSMutableDictionary *subscriptions = [self.manager.subscriptions mutableCopy];
    [subscriptions setObject:qos forKey:topic];
    [self.manager setSubscriptions:subscriptions];
}

- (void)unsubscribe:(NSString *)topic {
    NSMutableDictionary *subscriptions = [self.manager.subscriptions mutableCopy];
    [subscriptions removeObjectForKey:topic];
    [self.manager setSubscriptions:subscriptions];
}

- (void)publish:(NSString *)topic data:(NSData *)data qos:(NSNumber *)qos retain:(BOOL)retain {
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

- (void)dealloc {
    [self disconnect];
}

@end
