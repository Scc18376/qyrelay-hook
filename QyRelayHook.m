//
//  QyRelayHook.m
//  腾讯视频 iOS 9.04.66 / iOS 26.x 取流劫持 dylib
//
//  对位 Android 版 local.mobile.DefinitionRelay 的行为：
//    1. TVKHTTPRequest 的取流 URL → 改写指向授权服务端
//    2. vinfo 请求头注入 X-Local-Device-Id
//    3. 越狱/调试检测旁路（非越狱设备上主要是 ptrace / sysctl 探测）
//
//  编译: clang -arch arm64 -dynamiclib -fobjc-arc -framework Foundation \
//               -framework UIKit -o QyRelayHook.dylib QyRelayHook.m
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>
#import <sys/sysctl.h>
#import <dlfcn.h>

// ============================================================ 配置
// 编译期注入，或由 /var/mobile/.qyrelay.conf 覆盖
static NSString *const kDefaultRelayBase = @"http://43.142.65.109:8078/qyvide/client/";
static NSString *const kPrefDomain      = @"com.tencent.live4iphone.qyrelay";
static NSString *const kLocalIdKey      = @"local_id";

// ============================================================ 工具
static void QRLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[QyRelay] %@", s);
}

static NSString *QRConfigPath(void) {
    return @"/var/mobile/.qyrelay.conf";
}

static NSString *QRRelayBase(void) {
    static NSString *cached = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *p = QRConfigPath();
        NSString *base = nil;
        if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
            NSString *txt = [NSString stringWithContentsOfFile:p
                                                      encoding:NSUTF8StringEncoding
                                                         error:NULL];
            NSCharacterSet *nl = [NSCharacterSet newlineCharacterSet];
            for (NSString *line in [txt componentsSeparatedByCharactersInSet:nl]) {
                NSString *t = [line stringByTrimmingCharactersInSet:
                               [NSCharacterSet whitespaceCharacterSet]];
                if ([t hasPrefix:@"relay="]) {
                    base = [t substringFromIndex:6];
                }
            }
        }
        cached = base.length ? base : kDefaultRelayBase;
        if (![cached hasSuffix:@"/"]) cached = [cached stringByAppendingString:@"/"];
        QRLog(@"relay base = %@", cached);
    });
    return cached;
}

static NSString *QRLocalId(void) {
    static NSString *cached = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSUserDefaults *d = [[NSUserDefaults alloc] initWithSuiteName:kPrefDomain];
        NSString *v = [d stringForKey:kLocalIdKey];
        if (!v.length) {
            // 与 Android 版一致：UUID 去横线，32 位小写 hex
            v = [[[NSUUID UUID] UUIDString]
                 stringByReplacingOccurrencesOfString:@"-" withString:@""].lowercaseString;
            [d setObject:v forKey:kLocalIdKey];
            [d synchronize];
        }
        cached = v;
        QRLog(@"localId = %@", cached);
    });
    return cached;
}

// 判断是否是我们需要接管的取流请求
static BOOL QRIsVinfoPath(NSString *url) {
    if (![url isKindOfClass:[NSString class]] || url.length == 0) return NO;
    NSString *lower = url.lowercaseString;
    return [lower containsString:@"/getvinfo"] ||
           [lower containsString:@"/batchvinfo"] ||
           [lower containsString:@"/getvideo" ] ||
           [lower containsString:@"definitionauth"];
}

// 把腾讯的 URL 改写成我们的
static NSString *QRRewrite(NSString *orig) {
    if (!QRIsVinfoPath(orig)) return orig;
    @try {
        NSURLComponents *c = [NSURLComponents componentsWithString:orig];
        if (!c) return orig;
        NSString *path  = c.path ?: @"";
        NSString *query = c.percentEncodedQuery;

        // 只取需要的那一段做后缀
        NSString *tail = path;
        NSRange r = [tail rangeOfString:@"/getvinfo"];
        if (r.location == NSNotFound) r = [tail rangeOfString:@"/batchvinfo"];
        if (r.location == NSNotFound) r = [tail rangeOfString:@"/getvideo"];
        if (r.location == NSNotFound) r = [tail rangeOfString:@"/definitionauth"];
        if (r.location != NSNotFound) tail = [tail substringFromIndex:r.location];

        NSString *newUrl = [NSString stringWithFormat:@"%@%@%@%@",
                            QRRelayBase(), QRLocalId(), tail,
                            query.length ? [@"?" stringByAppendingString:query] : @""];
        QRLog(@"rewrite %@ -> %@", orig, newUrl);
        return newUrl;
    } @catch (NSException *e) {
        QRLog(@"rewrite exception: %@", e);
        return orig;
    }
}

// ============================================================ Hook: URL 改写
static void QRInstallURLHooks(void) {
    // 1) TVKHTTPRequest 系列
    NSArray *classes = @[@"TVKHTTPRequest",
                         @"TVKNSURLSessionHTTPRequest",
                         @"TVKATSHTTPRequest"];
    NSArray *sels = @[@"getUrl", @"URL", @"url", @"mUrl",
                      @"requestURL", @"originalURL", @"URLString"];

    for (NSString *cn in classes) {
        Class cls = NSClassFromString(cn);
        if (!cls) continue;
        for (NSString *sn in sels) {
            SEL sel = NSSelectorFromString(sn);
            Method m = class_getInstanceMethod(cls, sel);
            if (!m) continue;
            const char *types = method_getTypeEncoding(m);
            if (!types || types[0] != '@') continue;   // 只处理返回对象的方法

            IMP orig = method_getImplementation(m);
            IMP newImp = imp_implementationWithBlock(^id(id self) {
                NSString *v = ((id(*)(id, SEL))orig)(self, sel);
                if ([v isKindOfClass:[NSString class]]) return QRRewrite(v);
                if ([v isKindOfClass:[NSURL class]]) {
                    NSString *s = [(NSURL *)v absoluteString];
                    NSString *n = QRRewrite(s);
                    return [n isEqualToString:s] ? v : [NSURL URLWithString:n];
                }
                return v;
            });
            class_replaceMethod(cls, sel, newImp, types);
            QRLog(@"hooked -[%@ %@]", cn, sn);
        }
    }

    // 2) NSURLRequest 构造（兜底：部分路径直接 new NSURLRequest）
    Class R = NSClassFromString(@"NSURLRequest");
    Method m1 = class_getInstanceMethod(R, @selector(URL));
    if (m1) {
        IMP orig = method_getImplementation(m1);
        IMP ni = imp_implementationWithBlock(^id(id self) {
            NSURL *u = ((id(*)(id, SEL))orig)(self, @selector(URL));
            NSString *s = u.absoluteString;
            NSString *n = QRRewrite(s);
            return [n isEqualToString:s] ? u : [NSURL URLWithString:n];
        });
        class_replaceMethod(R, @selector(URL), ni, method_getTypeEncoding(m1));
        QRLog(@"hooked -[NSURLRequest URL]");
    }
}

// ============================================================ Hook: 请求头注入
static void QRInstallHeaderHooks(void) {
    // vinfo 请求头字典的 setter / getter
    SEL sels[] = {
        NSSelectorFromString(@"setVinfoRequestHeaders:"),
        NSSelectorFromString(@"setExtraVinfoRequestHeadersMap:"),
        NSSelectorFromString(@"vinfoRequestHeaders"),
        NSSelectorFromString(@"extraVinfoRequestHeadersMap"),
    };

    unsigned int n = 0;
    Class *all = objc_copyClassList(&n);
    int hooked = 0;
    for (unsigned int i = 0; i < n; i++) {
        Class c = all[i];
        NSString *cn = NSStringFromClass(c);
        if (![cn hasPrefix:@"TVK"] && ![cn hasPrefix:@"QL"] && ![cn hasPrefix:@"MLV"]) continue;

        for (int k = 0; k < 4; k++) {
            SEL curSel = sels[k];
            Method m = class_getInstanceMethod(c, curSel);
            if (!m) continue;
            const char *types = method_getTypeEncoding(m);
            if (!types) continue;
            IMP orig = method_getImplementation(m);

            if (types[0] == 'v') {          // setter: 注入后转原实现
                IMP ni = imp_implementationWithBlock(^(id self, NSMutableDictionary *d) {
                    if ([d isKindOfClass:[NSMutableDictionary class]]) {
                        d[@"X-Local-Device-Id"] = QRLocalId();
                    }
                    ((void(*)(id, SEL, id))orig)(self, curSel, d);
                });
                class_replaceMethod(c, curSel, ni, types);
                hooked++;
            } else if (types[0] == '@') {    // getter: 返回前补
                IMP ni = imp_implementationWithBlock(^id(id self) {
                    id r = ((id(*)(id, SEL))orig)(self, curSel);
                    if ([r isKindOfClass:[NSMutableDictionary class]]) {
                        r[@"X-Local-Device-Id"] = QRLocalId();
                    }
                    return r;
                });
                class_replaceMethod(c, curSel, ni, types);
                hooked++;
            }
        }
    }
    free(all);
    QRLog(@"header hooks installed: %d", hooked);
}

// ============================================================ Hook: 检测旁路
static void QRInstallAntiDetection(void) {
    // 1) ptrace 直接返回 0（防调试）
    // 用 fishhook 方式太重，这里用 runtime swizzle 不了 C 函数，
    // 改为在关键类上覆盖 isJailbroken 类方法。
    NSArray *selNames = @[@"isJailbreak", @"isJailbroken", @"jsJailbreak",
                          @"isDeviceJailbroken", @"checkJailbreak"];
    NSArray *prefixes = @[@"QL", @"TVK", @"Pandora", @"MLV", @"QAD"];

    unsigned int n = 0;
    Class *all = objc_copyClassList(&n);
    int hooked = 0;
    for (unsigned int i = 0; i < n; i++) {
        Class c = all[i];
        NSString *cn = NSStringFromClass(c);
        BOOL match = NO;
        for (NSString *p in prefixes) if ([cn hasPrefix:p]) { match = YES; break; }
        if (!match) continue;

        for (NSString *sn in selNames) {
            SEL sel = NSSelectorFromString(sn);
            Method m = class_getInstanceMethod(c, sel);
            if (!m) continue;
            const char *types = method_getTypeEncoding(m);
            if (!types || types[0] != 'c' && types[0] != 'B') continue;
            IMP ni = imp_implementationWithBlock(^BOOL(id self) { return NO; });
            class_replaceMethod(c, sel, ni, types);
            hooked++;
            QRLog(@"anti-detect: -[%@ %@] -> NO", cn, sn);
        }
    }
    free(all);
    QRLog(@"anti-detection hooks: %d", hooked);
}

// ============================================================ 启动
__attribute__((constructor))
static void QyRelayInit(void) {
    @autoreleasepool {
        QRLog(@"=== QyRelayHook loaded (pid %d) ===", getpid());

        // 延迟到主线程 RunLoop 启动后，避免早期 class 未加载
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            QRInstallAntiDetection();
            QRInstallURLHooks();
            QRInstallHeaderHooks();
            QRLog(@"init done. relay=%@ localId=%@", QRRelayBase(), QRLocalId());
        });
    }
}
