# Objective-C packet tunnel integration

`HajimiPacketTunnelProvider` is a buildable NetworkExtension packet-flow adapter,
not a replacement TCP/IP stack. It feeds each raw IP packet read from
`NEPacketTunnelFlow` to `submit_packet` and writes only actual engine output back
to the flow. There is no discard loop, fake forwarding, private utun descriptor
access, or fallback to a plaintext proxy.

## Current activation boundary

The provider is **not operational without a complete shared native packet
engine** implementing `HJPacketEngineBridge.h`. The existing C packet codec and
Objective-C byte-stream relay do not meet that contract. If the factory returns
no API, is incompatible, or lacks the required IP/TCP/UDP capabilities, startup
fails before calling `setTunnelNetworkSettings`. The built-in legacy Swift utun
flow engine is not silently loaded into this Objective-C extension.

The host also needs Apple-authorized signing/provisioning for
`com.apple.developer.networking.networkextension` with `packet-tunnel-provider`.
The extension must be embedded in `Hajimi.app/Contents/PlugIns`, have the exact
bundle identifier `app.hajimi.PacketTunnel`, and be signed/provisioned with a
compatible team. `Host.entitlements` and `Provider.entitlements` are templates;
adding an entitlement to an ad-hoc signature does not grant Apple's permission.
If using a distribution channel that requires a system extension instead of an
app extension, its installation/activation integration must be implemented
separately; this template does not claim support for that packaging.

No build or test here installs an extension, starts a VPN, writes preferences,
or changes system proxy, DNS, or routes. The host controller only does those
manager operations after an explicit caller request. Saving does not start the
tunnel and disables on-demand activation for this provider.

## Compile-only development build

```sh
sh NetworkExtension/build-provider.sh
```

The output is an unsigned `.build/NetworkExtension/HajimiPacketTunnel.appex`.
It links with the public `NSExtensionMain` entry point. The default build has no
native engine and intentionally cannot capture traffic. A real static engine
can be linked explicitly:

```sh
HJ_PACKET_ENGINE_LIBRARY=/absolute/path/to/libhajimi_packet_engine.a \
  sh NetworkExtension/build-provider.sh
```

The archive is force-loaded so its strong factory replaces the weak NULL-API
unavailable sentinel. The sentinel never receives or discards packets. Engine
authors should define `HJ_PACKET_ENGINE_IMPLEMENTATION` before including the
ABI header in the implementation. Any further native-library dependencies must
be linked in the provider build/Xcode target as appropriate.

Signing, provisioning, embedding, and user-approved activation remain separate
release steps. Verify the engine's packet-level interoperability and its socket
escape/binding behavior before enabling default routes. A complete engine must
implement actual TCP flow state, UDP routing, configured policy/protocol
outbounds, and failure/backpressure handling; it must synchronously quiesce its
callbacks during stop. Do not advertise the extension as working based solely
on a successful compile.

## Explicit provider configuration

Pass an immutable property-list dictionary to
`HJNetworkExtensionController.save(configuration:description:completion:)`.
`engineConfiguration` is nonempty `NSData` (up to 8 MiB), encoded according to
the linked engine's own format. Network settings are separate and explicit:

```text
engineConfiguration: <engine-owned serialized NSData>
tunnelRemoteAddress: "198.18.0.1"
ipv4:
  address: "198.18.0.2"
  subnetMask: "255.255.255.252"
  includedRoutes:
    - { destination: "0.0.0.0", subnetMask: "0.0.0.0" }
  excludedRoutes: []
dnsServers: ["198.18.0.1"]
mtu: 1500
```

These are examples of the data shape, not a working profile: the native engine
must actually serve/route the DNS address and implement the requested flows.
No default route is inferred when `includedRoutes` is missing. Route entries
must use canonical network addresses, contiguous IPv4 masks, or IPv6 prefixes.
Optional `ipv6` uses `address`, `prefixLength`, and route dictionaries containing
`destination` and `prefixLength`. If omitted, this extension handles only IPv4;
it is not an IPv6 kill switch. MTU must be 576–9000 (at least 1280 with IPv6).

Raw packet callbacks use Darwin `AF_INET`/`AF_INET6` values, not numeric IP
versions, and do not include the utun frame prefix. Output is validated and
bounded to prevent unbounded queues; engine errors, invalid packets, or a failed
packet-flow write cancel the tunnel instead of reporting successful forwarding.
The provider defers stop completion while a network-settings request is in
flight, so a late settings callback cannot outlive the stopped lifecycle.

## Swift host API

`HJNetworkExtensionController` exposes `availabilityError`, `status`,
`statusDescription`, `hasSavedConfiguration`, `statusDidChangeHandler`, and
`load`, `save`, `start`, `stop` methods. Callbacks run on the main queue. Start
completion acknowledges the start request; connection readiness is reported by
status changes. The controller only touches configurations with this provider's
bundle identifier. Multiple matching configurations produce an explicit error;
no third-party VPN is selected, modified, stopped, or deleted.

`HJTrafficDashboardView` is a separate Objective-C AppKit view for aggregated
upload/download rates and active connections. Its fixed 60-sample history and
10 Hz redraw coalescing avoid driving UI work directly from every packet.
