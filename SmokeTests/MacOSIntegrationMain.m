#import "HajimiMacOSObjC.h"
#include <stdio.h>

int main(void) {
    @autoreleasepool {
        HJNetworkExtensionController *controller = [[HJNetworkExtensionController alloc] init];
        // This unsigned command-line fixture must fail preflight; it never
        // loads/saves VPN preferences or calls start/stop on a manager.
        NSError *error = controller.availabilityError;
        if (!error || error.code != HJNetworkExtensionErrorMissingEntitlement ||
            controller.hasSavedConfiguration || controller.status != NEVPNStatusInvalid) {
            fputs("Network Extension preflight failed to enforce entitlement boundary\n", stderr);
            return 1;
        }
        HJTrafficDashboardView *view = [[HJTrafficDashboardView alloc] initWithFrame:NSMakeRect(0, 0, 640, 126)];
        if (!view || !view.isFlipped) return 2;
        [view updateWithUploadBytesPerSecond:1024 downloadBytesPerSecond:2048 activeConnections:4];
        [view reset];

        HJStatusBarHeaderView *headerView = [[HJStatusBarHeaderView alloc] initWithFrame:NSMakeRect(0, 0, 316, 102)];
        if (!headerView || !headerView.isFlipped) return 3;
        [headerView updateWithRunning:YES
                         enhancedMode:YES
                          systemProxy:YES
                            modeTitle:@"全局代理"
                       activeNodeName:@"🇯🇵 东京 IEPL 01"
                        latencyMillis:36
                 uploadBytesPerSecond:65536
               downloadBytesPerSecond:4194304
                   totalUploadedBytes:10485760
                 totalDownloadedBytes:524288000
                    activeConnections:12];
        puts("Objective-C dashboard / status-bar header / Network Extension fail-closed preflight passed (no network changes)");
    }
    return 0;
}
