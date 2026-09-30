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
        puts("Objective-C dashboard / Network Extension fail-closed preflight passed (no network changes)");
    }
    return 0;
}
