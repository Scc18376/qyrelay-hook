//
//  QyRelayHook.m  v2 — 诊断优先版
//  启动即上报，不做任何 hook 判断，用于确认 dylib 是否被加载
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>

static NSString *const kRelayBase = @"http://43.142.65.109:8078";
static NSString *const kPrefDomain = @"com.tencent.live4iphone.qyrelay";
static NSString *const kLocalIdKey = @"local_id";

static void LOG(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSLog(@"[QyRelay] %@", [[NSString alloc] initWithFormat:fmt arguments:ap]);
    va_end(ap);
}

static NSString *LocalId(void) {
    static NSString *cached = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSUserDefaults *d = [[NSUserDefaults alloc] initWithSuiteName:kPrefDomain];
        NSString *v = [d stringForKey:kLocalIdKey];
        if (!v.length) {
            v = [[[NSUUID UUID] UUIDString]
                 stringByReplacingOccurrencesOfString:@"-" withString:@""].lowercaseString;
            [d setObject:v forKey:kLocalIdKey];
            [d synchronize];
        }
        cached = v;
    });
    return cached;
}

// 无条件上报：确认 dylib 活了
static void Beacon(void) {
    @autoreleasepool {
        NSString *lid = LocalId();
        NSString *url = [NSString stringWithFormat:@"%@/qyvide/client/%@/getvinfo?vid=boot&platform=10503",
                         kRelayBase, lid];
        LOG(@"BEACON start lid=%@", lid);
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
        req.HTTPMethod = @"GET";
        req.timeoutInterval = 12;
        [req setValue:lid forHTTPHeaderField:@"X-Local-Device-Id"];
        [req setValue:@"QyRelay-iOS" forHTTPHeaderField:@"X-QyRelay"];

        NSURLSession *s = [NSURLSession sessionWithConfiguration:
                           [NSURLSessionConfiguration defaultSessionConfiguration]];
        [[s dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
            NSInteger code = [(NSHTTPURLResponse *)resp statusCode];
            NSString *body = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"";
            LOG(@"BEACON done code=%ld body=%@ err=%@", (long)code, body, err.localizedDescription);
        }] resume];
    }
}

// 挂文件日志，方便无电脑排查
static void FileLog(NSString *s) {
    NSString *p = @"/var/mobile/qyrelay.log";
    NSString *line = [NSString stringWithFormat:@"%@ %@\n",
                      [NSDate date], s];
    FILE *f = fopen(p.UTF8String, "a");
    if (f) { fputs(line.UTF8String, f); fclose(f); }
}

__attribute__((constructor))
static void QyRelayInit(void) {
    @autoreleasepool {
        LOG(@"=== QyRelay v2 loaded pid=%d ===", getpid());
        FileLog(@"=== v2 loaded ===");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            Beacon();
        });
    }
}
