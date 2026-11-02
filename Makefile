APP_NAME := 哈基米
APP_VERSION := 0.1.0
EXECUTABLE_NAME := Hajimi
BUILD_CONFIG := release
DIST_DIR := dist
APP_BUNDLE := $(DIST_DIR)/$(APP_NAME).app

# Build native C/C++ libraries for the host by default. Universal builds also
# require OpenSSL static archives containing both requested slices.
ARCHS ?= $(shell uname -m)
SWIFT_ARCH_FLAGS := $(foreach arch,$(ARCHS),--arch $(arch))
ARCHIVE_FLAVOR := $(if $(word 2,$(ARCHS)),universal,$(firstword $(ARCHS)))

# SwiftPM writes single-architecture builds under a target triple directory and
# lipo'd multi-architecture builds under .build/apple/Products/<Config>.
ifeq ($(words $(ARCHS)),1)
BUILD_DIR := .build/$(ARCHS)-apple-macosx/$(BUILD_CONFIG)
else
BUILD_DIR := .build/apple/Products/$(if $(filter release,$(BUILD_CONFIG)),Release,Debug)
endif

.PHONY: all native-core build app icon clean run test test-native test-icons test-rules test-compiled-rules test-dns-settings test-dns-cache benchmark-dns-wire test-dns test-dns-performance test-enhanced-startup test-network-performance test-network-resources test-carrier-framing test-optional-carriers test-native-tunnel-packet-load test-video-streams test-transfer-copy test-cpp-post-dispatch test-cpp test-quic test-chains network-extension verify archive

export MACOSX_DEPLOYMENT_TARGET := 13.0
HAJIMI_OPENSSL_ROOT ?= $(if $(wildcard /opt/homebrew/opt/openssl@3/include/openssl/ssl.h),/opt/homebrew/opt/openssl@3,/usr/local/opt/openssl@3)
export HAJIMI_OPENSSL_ROOT
CPP_SMOKE_DIR := .build/cpp-protocol-tests
CPP_PROTOCOL_SOURCES := $(wildcard Sources/HajimiProtocolsCXX/*.cpp)
CPP_PROTOCOL_HEADERS := $(wildcard Sources/HajimiProtocolsCXX/*.hpp Sources/HajimiProtocolsCXX/include/*.h)
CPP_PROTOCOL_OBJECTS := $(patsubst Sources/HajimiProtocolsCXX/%.cpp,$(CPP_SMOKE_DIR)/%.o,$(CPP_PROTOCOL_SOURCES))
CPP_INCLUDES := -I Sources/HajimiProtocolsCXX -I Sources/HajimiProtocolCXX/include -I "$(HAJIMI_OPENSSL_ROOT)/include" -I .build/Vendor/HajimiQUIC/include -I .build/Vendor/HajimiSSH/include
CPP_LIBRARIES := .build/Vendor/HajimiQUIC/lib/libngtcp2_crypto_ossl.a .build/Vendor/HajimiQUIC/lib/libngtcp2.a .build/Vendor/HajimiQUIC/lib/libnghttp3.a .build/Vendor/HajimiSSH/lib/libssh2.a "$(HAJIMI_OPENSSL_ROOT)/lib/libssl.a" "$(HAJIMI_OPENSSL_ROOT)/lib/libcrypto.a" -framework Security -framework CoreFoundation
CPP_TEST_FLAGS := -std=c++17 -O1 -g -Wall -Wextra -Werror
# Optional environment for executable smoke fixtures only. Do not redirect
# SwiftPM's own HOME/TMPDIR; its toolchain/cache subprocesses are not fixtures.
TEST_ENV ?=
RULE_TEST_DIR := .build/rule-tests
RULE_TEST_FLAGS := -target $(shell uname -m)-apple-macos13.0
ROUTING_MODULE_TEST_DIR := .build/routing-module-tests
ROUTING_MODULE_SOURCES := $(wildcard Sources/HajimiRouting/*.swift)
ROUTING_TEST_FLAGS := -package-name Hajimi -I "$(ROUTING_MODULE_TEST_DIR)" -L "$(ROUTING_MODULE_TEST_DIR)" -lHajimiRouting -Xlinker -rpath -Xlinker "$(abspath $(ROUTING_MODULE_TEST_DIR))"
COMPILED_RULE_TEST_DIR := .build/compiled-rule-tests
DNS_SETTINGS_TEST_DIR := .build/dns-settings-tests
DNS_CACHE_TEST_DIR := .build/dns-cache-tests
DNS_MODULE_TEST_DIR := .build/dns-module-tests
DNS_MODULE_SOURCES := $(wildcard Sources/HajimiDNS/*.swift)
DNS_WIRE_TEST_DIR := .build/dns-wire-tests
DNS_WIRE_ITERATIONS ?= 20000
CARRIER_FRAMING_TEST_DIR := .build/carrier-framing-tests
OPTIONAL_CARRIER_TEST_DIR := .build/optional-carrier-tests
TRANSFER_TEST_DIR := .build/transfer-copy-tests
RESOURCE_TEST_DIR := .build/network-resources-tests
RUNTIME_TEST_DIR := .build/runtime-tests
MAIN_LIFECYCLE_TEST_DIR := .build/main-lifecycle-tests
UI_COMPONENTS_TEST_DIR := .build/ui-components-tests
UI_COMPONENTS_SOURCES := $(wildcard Sources/HajimiUIComponents/*.swift)
UI_COMPONENTS_TEST_FLAGS := -I "$(UI_COMPONENTS_TEST_DIR)" -L "$(UI_COMPONENTS_TEST_DIR)" -lHajimiUIComponents -Xlinker -rpath -Xlinker "$(abspath $(UI_COMPONENTS_TEST_DIR))"
DIAGNOSTICS_UI_TEST_DIR := .build/diagnostics-ui-module-tests

all: app

.PHONY: test-runtime test-main-lifecycle test-dns-module test-routing-module test-diagnostics-ui-module test-dns-cold-admission test-dns-post-send-recovery test-dns-query-health test-enhanced-reconnect test-dns-query-io

# Anonymous PTR shape and per-lease I/O evidence; memory-only production owners.
test-dns-query-io:
	python3 scripts/test_dns_ptr_query_shape.py
	python3 scripts/test_dns_query_io_progress.py
	python3 scripts/test_native_tls_stream_progress.py

# PTR and ordinary answer-health isolation; exact owners with memory peers only.
test-dns-query-health:
	python3 scripts/test_dns_query_health_isolation.py
	python3 scripts/test_dns_fallback_health_isolation.py

# Physical-uplink deferral, owned IPC replies and real observer/debounce wiring, memory only.
test-enhanced-reconnect:
	python3 scripts/test_enhanced_reconnect_helper.py
	python3 scripts/test_enhanced_startup.py --client-only
	python3 scripts/test_enhanced_handoff.py

# Original-deadline recovery and anonymous PTR metadata, memory only.
test-dns-post-send-recovery:
	python3 scripts/test_dns_post_send_recovery.py
	python3 scripts/test_dns_ptr_classification.py

# Full approved-provider admission and real DoH/DoT cold-queue snapshots, memory only.
test-dns-cold-admission:
	python3 scripts/test_dns_cold_provider_admission.py
	python3 scripts/test_dns_cold_queue_availability.py

# Standalone ownership checks: Foundation only, without App/Core/native builds.
test-runtime:
	mkdir -p "$(RUNTIME_TEST_DIR)"
	xcrun swiftc -O -swift-version 5 $(RULE_TEST_FLAGS) -parse-as-library -emit-module -emit-library -module-name HajimiRuntime Sources/HajimiRuntime/*.swift -emit-module-path "$(RUNTIME_TEST_DIR)/HajimiRuntime.swiftmodule" -Xlinker -install_name -Xlinker '@rpath/libHajimiRuntime.dylib' -o "$(RUNTIME_TEST_DIR)/libHajimiRuntime.dylib"
	xcrun swiftc -O -swift-version 5 $(RULE_TEST_FLAGS) -parse-as-library -emit-module -emit-library -module-name HajimiRuntimeTestSupport -I "$(RUNTIME_TEST_DIR)" -L "$(RUNTIME_TEST_DIR)" -lHajimiRuntime Sources/HajimiRuntimeTestSupport/*.swift -emit-module-path "$(RUNTIME_TEST_DIR)/HajimiRuntimeTestSupport.swiftmodule" -Xlinker -install_name -Xlinker '@rpath/libHajimiRuntimeTestSupport.dylib' -Xlinker -rpath -Xlinker '@loader_path' -o "$(RUNTIME_TEST_DIR)/libHajimiRuntimeTestSupport.dylib"
	xcrun swiftc -O -swift-version 5 $(RULE_TEST_FLAGS) -parse-as-library -I "$(RUNTIME_TEST_DIR)" -L "$(RUNTIME_TEST_DIR)" -lHajimiRuntime -lHajimiRuntimeTestSupport -Xlinker -rpath -Xlinker '@loader_path' SmokeTests/RuntimeCoordinatorMain.swift -o "$(RUNTIME_TEST_DIR)/runtime-coordinator-check"
	$(TEST_ENV) "$(RUNTIME_TEST_DIR)/runtime-coordinator-check"

# Actual controller entrypoints with memory-only owners and queued rule preparation.
test-main-lifecycle:
	python3 scripts/test_main_lifecycle.py --work-dir "$(MAIN_LIFECYCLE_TEST_DIR)"

$(UI_COMPONENTS_TEST_DIR)/libHajimiUIComponents.dylib: $(UI_COMPONENTS_SOURCES) Makefile
	mkdir -p "$(UI_COMPONENTS_TEST_DIR)"
	xcrun swiftc -O -swift-version 5 $(RULE_TEST_FLAGS) -parse-as-library -emit-module -emit-library -module-name HajimiUIComponents $(UI_COMPONENTS_SOURCES) -emit-module-path "$(UI_COMPONENTS_TEST_DIR)/HajimiUIComponents.swiftmodule" -Xlinker -install_name -Xlinker '@rpath/libHajimiUIComponents.dylib' -o "$@"

# Imports the shared diagnostics test-support entrypoint from completed modules.
# Runs twice in one process without launching the App or using platform I/O.
test-diagnostics-ui-module:
	python3 scripts/test_diagnostics_ui_module.py --configuration "$(BUILD_CONFIG)" --build-dir "$(BUILD_DIR)" --work-dir "$(DIAGNOSTICS_UI_TEST_DIR)"

# The routing module has no Core, platform transport or C++ dependencies.
$(ROUTING_MODULE_TEST_DIR)/libHajimiRouting.dylib: $(ROUTING_MODULE_SOURCES) Makefile
	mkdir -p "$(ROUTING_MODULE_TEST_DIR)"
	xcrun swiftc -O -swift-version 5 -package-name Hajimi $(RULE_TEST_FLAGS) -parse-as-library -emit-module -emit-library -module-name HajimiRouting $(ROUTING_MODULE_SOURCES) -emit-module-path "$(ROUTING_MODULE_TEST_DIR)/HajimiRouting.swiftmodule" -Xlinker -install_name -Xlinker '@rpath/libHajimiRouting.dylib' -o "$@"

test-routing-module:
	python3 scripts/test_routing_module.py --work-dir "$(ROUTING_MODULE_TEST_DIR)"

# Compile the complete DNS module independently, then exercise its imported API.
$(DNS_MODULE_TEST_DIR)/libHajimiDNS.dylib: $(DNS_MODULE_SOURCES) Makefile
	mkdir -p "$(DNS_MODULE_TEST_DIR)"
	xcrun swiftc -O -swift-version 5 -package-name Hajimi $(RULE_TEST_FLAGS) -parse-as-library -emit-module -emit-library -module-name HajimiDNS $(DNS_MODULE_SOURCES) -emit-module-path "$(DNS_MODULE_TEST_DIR)/HajimiDNS.swiftmodule" -Xlinker -install_name -Xlinker '@rpath/libHajimiDNS.dylib' -o "$@"

test-dns-module: $(DNS_MODULE_TEST_DIR)/libHajimiDNS.dylib
	xcrun swiftc -O -swift-version 5 -package-name Hajimi $(RULE_TEST_FLAGS) -parse-as-library -I "$(DNS_MODULE_TEST_DIR)" -L "$(DNS_MODULE_TEST_DIR)" -lHajimiDNS -Xlinker -rpath -Xlinker '@loader_path' SmokeTests/DNSModuleMain.swift -o "$(DNS_MODULE_TEST_DIR)/dns-module-check"
	$(TEST_ENV) "$(DNS_MODULE_TEST_DIR)/dns-module-check"

native-core:
	HAJIMI_ARCHS="$(ARCHS)" ./scripts/build_native_core.sh

build: native-core
	swift build -c $(BUILD_CONFIG) $(SWIFT_ARCH_FLAGS) -Xcc "-I$(CURDIR)/Sources/HajimiProtocolsCXX/VendorInclude" -Xcc "-I$(CURDIR)/.build/Vendor/OpenSSL/include" -Xcc "-I$(CURDIR)/.build/Vendor/HajimiQUIC/include" -Xcc "-I$(CURDIR)/.build/Vendor/HajimiSSH/include"

icon:
	python3 scripts/generate_icon.py

test-icons: icon
	mkdir -p .build/icon-tests
	xcrun swiftc -target $(shell uname -m)-apple-macos13.0 -framework AppKit Sources/HajimiApp/StatusBarCatIcon.swift Sources/HajimiApp/HajimiBrandIcon.swift SmokeTests/IconAssetsMain.swift -o .build/icon-tests/icon-check
	.build/icon-tests/icon-check Resources

$(COMPILED_RULE_TEST_DIR)/%.o: Sources/HajimiRoutingCXX/%.cpp Sources/HajimiRoutingCXX/include/HajimiRoutingCXX.h
	mkdir -p "$(COMPILED_RULE_TEST_DIR)"
	clang++ -std=c++17 -O2 -Wall -Wextra -Werror -I Sources/HajimiRoutingCXX/include -c "$<" -o "$@"

test-compiled-rules: $(COMPILED_RULE_TEST_DIR)/DomainMatcher.o $(COMPILED_RULE_TEST_DIR)/CompiledRules.o $(ROUTING_MODULE_TEST_DIR)/libHajimiRouting.dylib
	clang++ -std=c++17 -O2 -Wall -Wextra -Werror -pthread -I Sources/HajimiRoutingCXX/include Sources/HajimiRoutingCXX/CompiledRules.cpp SmokeTests/CompiledRulesMain.cpp -o "$(COMPILED_RULE_TEST_DIR)/native-compiled-rule-check"
	"$(COMPILED_RULE_TEST_DIR)/native-compiled-rule-check"
	xcrun swiftc -O $(RULE_TEST_FLAGS) $(ROUTING_TEST_FLAGS) -Xcc "-fmodule-map-file=$(CURDIR)/SmokeTests/HajimiRoutingCXX.modulemap" Sources/HajimiCore/Profile.swift Sources/HajimiCore/SurgeProfileDocument.swift Sources/HajimiCore/NativeDomainMatcher.swift Sources/HajimiCore/CompiledRoutingRules.swift Sources/HajimiCore/CompiledRoutingRulesSelfTest.swift SmokeTests/CompiledRoutingRulesMain.swift $(COMPILED_RULE_TEST_DIR)/DomainMatcher.o $(COMPILED_RULE_TEST_DIR)/CompiledRules.o -Xlinker -lc++ -o "$(COMPILED_RULE_TEST_DIR)/compiled-rule-check"
	$(TEST_ENV) "$(COMPILED_RULE_TEST_DIR)/compiled-rule-check"

test-rules: test-compiled-rules
	mkdir -p "$(RULE_TEST_DIR)"
	xcrun swiftc $(RULE_TEST_FLAGS) $(ROUTING_TEST_FLAGS) Sources/HajimiCore/Profile.swift Sources/HajimiCore/SurgeProfileDocument.swift Sources/HajimiApp/RuleTableSelection.swift SmokeTests/RuleEditingMain.swift -o "$(RULE_TEST_DIR)/rule-editing-check"
	"$(RULE_TEST_DIR)/rule-editing-check"
	xcrun swiftc $(RULE_TEST_FLAGS) Sources/HajimiApp/ProfileApplyCommitGuard.swift SmokeTests/RuleCommitGuardMain.swift -o "$(RULE_TEST_DIR)/rule-commit-guard-check"
	"$(RULE_TEST_DIR)/rule-commit-guard-check"
	xcrun swiftc $(RULE_TEST_FLAGS) Sources/HajimiApp/RuleSetBackgroundRefreshPlan.swift SmokeTests/RuleSetBackgroundRefreshMain.swift -o "$(RULE_TEST_DIR)/rule-background-refresh-check"
	"$(RULE_TEST_DIR)/rule-background-refresh-check"
	xcrun swiftc $(RULE_TEST_FLAGS) $(ROUTING_TEST_FLAGS) -parse-as-library -emit-module -emit-library -module-name HajimiCore Sources/HajimiCore/Profile.swift Sources/HajimiCore/SurgeProfileDocument.swift -emit-module-path "$(RULE_TEST_DIR)/HajimiCore.swiftmodule" -Xlinker -install_name -Xlinker '@rpath/libHajimiCore.dylib' -o "$(RULE_TEST_DIR)/libHajimiCore.dylib"
	xcrun swiftc $(RULE_TEST_FLAGS) $(ROUTING_TEST_FLAGS) -I "$(RULE_TEST_DIR)" -L "$(RULE_TEST_DIR)" -lHajimiCore -Xlinker -rpath -Xlinker "$(CURDIR)/$(RULE_TEST_DIR)" Sources/HajimiApp/SurgeRuleSetManager.swift SmokeTests/RuleSetRefreshMain.swift -o "$(RULE_TEST_DIR)/rule-refresh-check"
	"$(RULE_TEST_DIR)/rule-refresh-check"
	xcrun swiftc $(RULE_TEST_FLAGS) $(ROUTING_TEST_FLAGS) -I "$(RULE_TEST_DIR)" -L "$(RULE_TEST_DIR)" -lHajimiCore -Xlinker -rpath -Xlinker "$(CURDIR)/$(RULE_TEST_DIR)" Sources/HajimiApp/ListSearchIndex.swift Sources/HajimiApp/RuleListPreparation.swift SmokeTests/ListSearchPreparationMain.swift -o "$(RULE_TEST_DIR)/list-search-preparation-check"
	"$(RULE_TEST_DIR)/list-search-preparation-check"
	xcrun swiftc $(RULE_TEST_FLAGS) $(ROUTING_TEST_FLAGS) -framework AppKit -I "$(RULE_TEST_DIR)" -L "$(RULE_TEST_DIR)" -lHajimiCore -Xlinker -rpath -Xlinker "$(CURDIR)/$(RULE_TEST_DIR)" Sources/HajimiApp/RuleUIComponents.swift SmokeTests/RuleEditorUIMain.swift -o "$(RULE_TEST_DIR)/rule-editor-ui-check"
	"$(RULE_TEST_DIR)/rule-editor-ui-check"

test-dns-settings: $(ROUTING_MODULE_TEST_DIR)/libHajimiRouting.dylib $(UI_COMPONENTS_TEST_DIR)/libHajimiUIComponents.dylib
	mkdir -p "$(DNS_SETTINGS_TEST_DIR)"
	xcrun swiftc $(RULE_TEST_FLAGS) $(ROUTING_TEST_FLAGS) Sources/HajimiCore/Profile.swift Sources/HajimiCore/SurgeProfileDocument.swift SmokeTests/DNSSplitProfileMain.swift -o "$(DNS_SETTINGS_TEST_DIR)/dns-split-profile-check"
	$(TEST_ENV) "$(DNS_SETTINGS_TEST_DIR)/dns-split-profile-check"
	xcrun swiftc $(RULE_TEST_FLAGS) $(ROUTING_TEST_FLAGS) -parse-as-library -emit-module -emit-library -module-name HajimiCore Sources/HajimiCore/Profile.swift Sources/HajimiCore/SurgeProfileDocument.swift -emit-module-path "$(DNS_SETTINGS_TEST_DIR)/HajimiCore.swiftmodule" -Xlinker -install_name -Xlinker '@rpath/libHajimiCore.dylib' -o "$(DNS_SETTINGS_TEST_DIR)/libHajimiCore.dylib"
	xcrun swiftc $(RULE_TEST_FLAGS) $(ROUTING_TEST_FLAGS) $(UI_COMPONENTS_TEST_FLAGS) -framework AppKit -I "$(DNS_SETTINGS_TEST_DIR)" -L "$(DNS_SETTINGS_TEST_DIR)" -lHajimiCore -Xlinker -rpath -Xlinker "$(CURDIR)/$(DNS_SETTINGS_TEST_DIR)" Sources/HajimiApp/DNSSettingsForm.swift SmokeTests/DNSSettingsFormMain.swift -o "$(DNS_SETTINGS_TEST_DIR)/dns-settings-ui-check"
	$(TEST_ENV) "$(DNS_SETTINGS_TEST_DIR)/dns-settings-ui-check"
	xcrun swiftc $(RULE_TEST_FLAGS) $(ROUTING_TEST_FLAGS) $(UI_COMPONENTS_TEST_FLAGS) -framework AppKit -I "$(DNS_SETTINGS_TEST_DIR)" -L "$(DNS_SETTINGS_TEST_DIR)" -lHajimiCore -Xlinker -rpath -Xlinker "$(CURDIR)/$(DNS_SETTINGS_TEST_DIR)" Sources/HajimiApp/DNSSettingsForm.swift Sources/HajimiApp/ScrollableSettingsContentView.swift SmokeTests/ScrollableDNSSettingsMain.swift -o "$(DNS_SETTINGS_TEST_DIR)/dns-settings-scroll-check"
	$(TEST_ENV) "$(DNS_SETTINGS_TEST_DIR)/dns-settings-scroll-check"

test-dns-cache: $(DNS_MODULE_TEST_DIR)/libHajimiDNS.dylib
	mkdir -p "$(DNS_CACHE_TEST_DIR)"
	xcrun swiftc -O -package-name Hajimi $(RULE_TEST_FLAGS) -I "$(DNS_MODULE_TEST_DIR)" -L "$(DNS_MODULE_TEST_DIR)" -lHajimiDNS -Xlinker -rpath -Xlinker "$(abspath $(DNS_MODULE_TEST_DIR))" Sources/HajimiCore/NetworkPerformanceDiagnostics.swift SmokeTests/DNSServiceBindingCacheMain.swift -o "$(DNS_CACHE_TEST_DIR)/dns-cache-check"
	$(TEST_ENV) "$(DNS_CACHE_TEST_DIR)/dns-cache-check"

benchmark-dns-wire: $(DNS_MODULE_TEST_DIR)/libHajimiDNS.dylib
	mkdir -p "$(DNS_WIRE_TEST_DIR)"
	xcrun swiftc -O -whole-module-optimization -parse-as-library -package-name Hajimi $(RULE_TEST_FLAGS) -I "$(DNS_MODULE_TEST_DIR)" -L "$(DNS_MODULE_TEST_DIR)" -lHajimiDNS -Xlinker -rpath -Xlinker "$(abspath $(DNS_MODULE_TEST_DIR))" SmokeTests/DNSWirePerformanceMain.swift -o "$(DNS_WIRE_TEST_DIR)/dns-wire-benchmark"
	$(TEST_ENV) "$(DNS_WIRE_TEST_DIR)/dns-wire-benchmark" --iterations "$(DNS_WIRE_ITERATIONS)"

test-carrier-framing:
	bash SmokeTests/test_carrier_framing.sh --work-dir "$(CARRIER_FRAMING_TEST_DIR)"

test-optional-carriers:
	bash SmokeTests/test_optional_carriers.sh --work-dir "$(OPTIONAL_CARRIER_TEST_DIR)"

test-native-tunnel-packet-load: build
	python3 SmokeTests/native_tunnel_packet_load.py --binary "$(BUILD_DIR)/$(EXECUTABLE_NAME)"

test-enhanced-startup: build
	python3 scripts/test_enhanced_startup.py --build-dir "$(BUILD_DIR)"
	python3 scripts/test_enhanced_handoff.py
	$(MAKE) test-main-lifecycle
	$(TEST_ENV) "$(BUILD_DIR)/HajimiHelper" --self-test

app: build icon
	rm -rf "$(APP_BUNDLE)"
	mkdir -p "$(APP_BUNDLE)/Contents/MacOS" "$(APP_BUNDLE)/Contents/Resources"
	cp "$(BUILD_DIR)/$(EXECUTABLE_NAME)" "$(APP_BUNDLE)/Contents/MacOS/$(EXECUTABLE_NAME)"
	cp Resources/Info.plist "$(APP_BUNDLE)/Contents/Info.plist"
	cp Resources/Hajimi.icns "$(APP_BUNDLE)/Contents/Resources/Hajimi.icns"
	cp Resources/ThirdPartyNotices.txt "$(APP_BUNDLE)/Contents/Resources/ThirdPartyNotices.txt"
	cp "$(BUILD_DIR)/HajimiHelper" "$(APP_BUNDLE)/Contents/Resources/HajimiHelper"
	chmod +x "$(APP_BUNDLE)/Contents/Resources/HajimiHelper"
	chmod +x "$(APP_BUNDLE)/Contents/MacOS/$(EXECUTABLE_NAME)"
	./scripts/codesign_app.sh "$(APP_BUNDLE)"
	@echo "Built $(APP_BUNDLE) ($(ARCHS))"

$(CPP_SMOKE_DIR)/%.o: Sources/HajimiProtocolsCXX/%.cpp $(CPP_PROTOCOL_HEADERS) | native-core
	mkdir -p "$(CPP_SMOKE_DIR)"
	clang++ $(CPP_TEST_FLAGS) $(CPP_INCLUDES) -c "$<" -o "$@"

$(CPP_SMOKE_DIR)/ProtocolCodec.o: Sources/HajimiProtocolCXX/ProtocolCodec.cpp Sources/HajimiProtocolCXX/include/HajimiProtocolCXX.h
	mkdir -p "$(CPP_SMOKE_DIR)"
	clang++ $(CPP_TEST_FLAGS) -I Sources/HajimiProtocolCXX/include -c "$<" -o "$@"

test-cpp: $(CPP_PROTOCOL_OBJECTS) $(CPP_SMOKE_DIR)/ProtocolCodec.o
	@for name in Shadowsocks BasicProtocols AnyTLS Snell Server; do \
		clang++ $(CPP_TEST_FLAGS) $(CPP_INCLUDES) "SmokeTests/Cpp$${name}Main.cpp" $(CPP_PROTOCOL_OBJECTS) $(CPP_SMOKE_DIR)/ProtocolCodec.o $(CPP_LIBRARIES) -Wl,-dead_strip -o "$(CPP_SMOKE_DIR)/$$name-check" || exit 1; \
		"$(CPP_SMOKE_DIR)/$$name-check" || exit 1; \
	done
	clang++ $(CPP_TEST_FLAGS) $(CPP_INCLUDES) SmokeTests/CppSSHMain.cpp $(CPP_PROTOCOL_OBJECTS) $(CPP_SMOKE_DIR)/ProtocolCodec.o $(CPP_LIBRARIES) -Wl,-dead_strip -o "$(CPP_SMOKE_DIR)/SSH-check"
	@if [ ! -x .build/QUICInterop/bin/python ]; then python3 -m venv .build/QUICInterop; fi
	@if ! .build/QUICInterop/bin/python -c 'import paramiko' >/dev/null 2>&1; then .build/QUICInterop/bin/pip install --only-binary=:all: 'paramiko==3.5.1'; fi
	.build/QUICInterop/bin/python SmokeTests/cpp_ssh_interop.py --binary "$(CPP_SMOKE_DIR)/SSH-check"
	clang++ $(CPP_TEST_FLAGS) -fobjc-arc -fblocks $(CPP_INCLUDES) -I Sources/HajimiCXXProtocolBridge/include -I Sources/HajimiProxyRuntime/include SmokeTests/CppBridgeMain.mm Sources/HajimiCXXProtocolBridge/HajimiCXXProtocolBridge.mm Sources/HajimiProxyRuntime/HajimiProxyRuntime.mm $(CPP_PROTOCOL_OBJECTS) $(CPP_SMOKE_DIR)/ProtocolCodec.o $(CPP_LIBRARIES) -framework Foundation -framework Network -Wl,-dead_strip -o "$(CPP_SMOKE_DIR)/bridge-check"
	"$(CPP_SMOKE_DIR)/bridge-check"
	clang++ $(CPP_TEST_FLAGS) -fobjc-arc -fblocks $(CPP_INCLUDES) -I Sources/HajimiCXXProtocolBridge/include -I Sources/HajimiProxyRuntime/include SmokeTests/CppAnyTLSScopeMain.mm Sources/HajimiCXXProtocolBridge/HajimiCXXProtocolBridge.mm Sources/HajimiProxyRuntime/HajimiProxyRuntime.mm $(CPP_PROTOCOL_OBJECTS) $(CPP_SMOKE_DIR)/ProtocolCodec.o $(CPP_LIBRARIES) -framework Foundation -framework Network -Wl,-dead_strip -o "$(CPP_SMOKE_DIR)/anytls-scope-check"
	"$(CPP_SMOKE_DIR)/anytls-scope-check"
	clang++ $(CPP_TEST_FLAGS) -fobjc-arc -fblocks $(CPP_INCLUDES) -I Sources/HajimiCXXProtocolBridge/include -I Sources/HajimiProxyRuntime/include SmokeTests/CppSchedulingMain.mm Sources/HajimiCXXProtocolBridge/HajimiCXXProtocolBridge.mm Sources/HajimiProxyRuntime/HajimiProxyRuntime.mm $(CPP_PROTOCOL_OBJECTS) $(CPP_SMOKE_DIR)/ProtocolCodec.o $(CPP_LIBRARIES) -framework Foundation -framework Network -Wl,-dead_strip -o "$(CPP_SMOKE_DIR)/scheduling-check"
	"$(CPP_SMOKE_DIR)/scheduling-check"

test-quic: native-core
	sh scripts/test_cpp_quic.sh

test-chains: build
	python3 SmokeTests/live_proxy_chains.py --binary "$(BUILD_DIR)/$(EXECUTABLE_NAME)"
	python3 SmokeTests/live_proxies.py --binary "$(BUILD_DIR)/$(EXECUTABLE_NAME)"

test-dns: build test-dns-settings test-dns-cache test-dns-module
	$(TEST_ENV) "$(BUILD_DIR)/$(EXECUTABLE_NAME)" --dns-security-self-test
	$(TEST_ENV) "$(BUILD_DIR)/$(EXECUTABLE_NAME)" --dns-proxy-fallback-self-test
	bash scripts/test_dns_transport_cancellation.sh --configuration "$(BUILD_CONFIG)" --build-dir "$(BUILD_DIR)"
	python3 SmokeTests/live_dns.py --binary "$(BUILD_DIR)/$(EXECUTABLE_NAME)"
	python3 SmokeTests/live_dns_split.py --binary "$(BUILD_DIR)/$(EXECUTABLE_NAME)"
	$(TEST_ENV) "$(BUILD_DIR)/HajimiHelper" --self-test

test-dns-performance: build
	$(TEST_ENV) "$(BUILD_DIR)/$(EXECUTABLE_NAME)" --dns-performance-self-test
	python3 SmokeTests/live_dns_performance.py --binary "$(BUILD_DIR)/$(EXECUTABLE_NAME)"
	python3 SmokeTests/live_dns_third_rotation.py --binary "$(BUILD_DIR)/$(EXECUTABLE_NAME)"
	$(TEST_ENV) "$(BUILD_DIR)/$(EXECUTABLE_NAME)" --proxy-performance-smoke-test

test-cpp-post-dispatch:
	python3 scripts/test_cpp_post_dispatch.py

test-transfer-copy: test-cpp-post-dispatch $(CPP_PROTOCOL_OBJECTS) $(CPP_SMOKE_DIR)/ProtocolCodec.o
	mkdir -p "$(TRANSFER_TEST_DIR)"
	clang++ $(CPP_TEST_FLAGS) $(CPP_INCLUDES) SmokeTests/CppReaderPerformanceMain.cpp $(CPP_PROTOCOL_OBJECTS) $(CPP_SMOKE_DIR)/ProtocolCodec.o $(CPP_LIBRARIES) -Wl,-dead_strip -o "$(TRANSFER_TEST_DIR)/reader-check"
	$(TEST_ENV) "$(TRANSFER_TEST_DIR)/reader-check"
	clang -O2 -std=c11 -Wall -Wextra -Werror -I Sources/HajimiDataPlaneC/include -c Sources/HajimiDataPlaneC/hajimi_dataplane.c -o "$(TRANSFER_TEST_DIR)/dataplane.o"
	xcrun swiftc -O $(RULE_TEST_FLAGS) -Xcc "-fmodule-map-file=$(CURDIR)/SmokeTests/HajimiDataPlaneC.modulemap" Sources/HajimiNativeCore/CDataPlane.swift SmokeTests/TCPDataViewMain.swift "$(TRANSFER_TEST_DIR)/dataplane.o" -o "$(TRANSFER_TEST_DIR)/tcp-view-check"
	$(TEST_ENV) "$(TRANSFER_TEST_DIR)/tcp-view-check"

test-network-resources:
	mkdir -p "$(RESOURCE_TEST_DIR)"
	xcrun swiftc $(RULE_TEST_FLAGS) -parse-as-library Sources/HajimiCore/NetworkProcessResources.swift SmokeTests/NetworkProcessResourcesMain.swift -o "$(RESOURCE_TEST_DIR)/process-resource-check"
	$(TEST_ENV) "$(RESOURCE_TEST_DIR)/process-resource-check"

test-network-performance: build test-transfer-copy test-network-resources test-carrier-framing test-optional-carriers
	$(TEST_ENV) "$(BUILD_DIR)/$(EXECUTABLE_NAME)" --network-optimization-self-test
	$(TEST_ENV) "$(BUILD_DIR)/$(EXECUTABLE_NAME)" --native-dataplane-self-test
	python3 SmokeTests/native_tunnel_packet_load.py --binary "$(BUILD_DIR)/$(EXECUTABLE_NAME)"
	$(TEST_ENV) "$(BUILD_DIR)/$(EXECUTABLE_NAME)" --dns-performance-self-test
	bash scripts/test_dns_transport_cancellation.sh --configuration "$(BUILD_CONFIG)"
	bash scripts/test_dns_doh_burst.sh --configuration "$(BUILD_CONFIG)" --fd-limit 256 --prepare-process-resources --count 96 --framing length
	python3 SmokeTests/live_dns_adaptive.py --binary "$(BUILD_DIR)/$(EXECUTABLE_NAME)"
	python3 SmokeTests/live_dns_performance.py --binary "$(BUILD_DIR)/$(EXECUTABLE_NAME)"
	$(TEST_ENV) "$(BUILD_DIR)/$(EXECUTABLE_NAME)" --proxy-performance-smoke-test

test-video-streams: build
	$(TEST_ENV) "$(BUILD_DIR)/$(EXECUTABLE_NAME)" --native-tunnel-stream-self-test
	python3 SmokeTests/live_video_streams.py --binary "$(BUILD_DIR)/$(EXECUTABLE_NAME)"
	bash scripts/test_udp_fallback_policy.sh --configuration "$(BUILD_CONFIG)"

test-native: test-cpp
	sh scripts/test_cpp_quic_boundaries.sh
	mkdir -p .build/smoke-tests
	clang++ -std=c++17 -O2 -Wall -Wextra -Werror -I Sources/HajimiFlowCXX/include Sources/HajimiFlowCXX/FlowState.cpp SmokeTests/FlowStateMain.cpp -o .build/smoke-tests/flow-check
	.build/smoke-tests/flow-check
	clang++ -std=c++17 -O2 -fno-exceptions -fno-rtti -Wall -Wextra -Werror -I Sources/HajimiProtocolCXX/include Sources/HajimiProtocolCXX/ProtocolCodec.cpp SmokeTests/ProtocolCodecMain.cpp -o .build/smoke-tests/protocol-codec-check
	.build/smoke-tests/protocol-codec-check
	clang++ -std=c++17 -O2 -fobjc-arc -fblocks -Wall -Wextra -Werror -I Sources/HajimiProxyRuntime/include Sources/HajimiProxyRuntime/HajimiProxyRuntime.mm SmokeTests/NativeRuntimeMain.mm -framework Foundation -framework Network -framework Security -o .build/smoke-tests/native-runtime-check
	.build/smoke-tests/native-runtime-check
	clang -O2 -fobjc-arc -fblocks -Wall -Wextra -Werror -I Sources/HajimiMacOSObjC/include Sources/HajimiMacOSObjC/HJNetworkExtensionController.m Sources/HajimiMacOSObjC/HJTrafficDashboardView.m Sources/HajimiMacOSObjC/HJStatusBarHeaderView.m SmokeTests/MacOSIntegrationMain.m -framework Foundation -framework AppKit -framework NetworkExtension -framework Security -o .build/smoke-tests/macos-integration-check
	.build/smoke-tests/macos-integration-check

network-extension:
	sh NetworkExtension/build-provider.sh

test: build test-native test-chains test-icons test-rules test-dns-settings test-dns-module test-routing-module test-diagnostics-ui-module test-video-streams
	mkdir -p .build/smoke-tests
	swiftc $(RULE_TEST_FLAGS) $(ROUTING_TEST_FLAGS) Sources/HajimiCore/Profile.swift Sources/HajimiCore/SurgeProfileDocument.swift SmokeTests/main.swift -o .build/smoke-tests/profile-check
	.build/smoke-tests/profile-check
	clang++ -std=c++17 -O2 -Wall -Wextra -Werror -I Sources/HajimiRoutingCXX/include Sources/HajimiRoutingCXX/DomainMatcher.cpp SmokeTests/DomainMatcherMain.cpp -o .build/smoke-tests/domain-check
	.build/smoke-tests/domain-check
	$(TEST_ENV) $(BUILD_DIR)/$(EXECUTABLE_NAME) --native-quic-codec-test
	$(TEST_ENV) $(BUILD_DIR)/$(EXECUTABLE_NAME) --protocol-adapter-smoke-test
	$(TEST_ENV) $(BUILD_DIR)/$(EXECUTABLE_NAME) --proxy-performance-smoke-test
	$(TEST_ENV) $(BUILD_DIR)/HajimiHelper --self-test
	# Data-plane self-test now lives in the App (helper no longer links HajimiNativeCore).
	$(TEST_ENV) $(BUILD_DIR)/$(EXECUTABLE_NAME) --native-dataplane-self-test

verify: test test-quic app
	file "$(APP_BUNDLE)/Contents/MacOS/$(EXECUTABLE_NAME)"
	file "$(APP_BUNDLE)/Contents/Resources/HajimiHelper"
	@for arch in $(ARCHS); do \
		for binary in "$(APP_BUNDLE)/Contents/MacOS/$(EXECUTABLE_NAME)" "$(APP_BUNDLE)/Contents/Resources/HajimiHelper"; do \
			/usr/bin/lipo -archs "$$binary" | /usr/bin/grep -qw "$$arch" \
				|| { echo "$$binary is missing the $$arch slice"; exit 1; }; \
		done; \
	done
	@echo "Architecture slices verified: $(ARCHS)"
	/usr/bin/codesign --verify --deep --strict --verbose=2 "$(APP_BUNDLE)"
	/usr/bin/plutil -lint "$(APP_BUNDLE)/Contents/Info.plist"
	.build/icon-tests/icon-check Resources "$(APP_BUNDLE)"
	@! /usr/bin/nm "$(APP_BUNDLE)/Contents/MacOS/$(EXECUTABLE_NAME)" | /usr/bin/grep -E '(_runtime\.|_cgo_|_crosscall|_LurgeQUIC|_x_cgo_)' || { echo "Unexpected legacy Go bridge/runtime symbols"; exit 1; }
	$(TEST_ENV) "$(APP_BUNDLE)/Contents/MacOS/$(EXECUTABLE_NAME)" --ingress-security-self-test
	$(TEST_ENV) "$(APP_BUNDLE)/Contents/MacOS/$(EXECUTABLE_NAME)" --network-optimization-self-test
	$(TEST_ENV) "$(APP_BUNDLE)/Contents/MacOS/$(EXECUTABLE_NAME)" --proxy-performance-smoke-test
	$(TEST_ENV) "$(APP_BUNDLE)/Contents/Resources/HajimiHelper" --self-test

run: app
	open "$(APP_BUNDLE)"

archive: app
	rm -f "$(DIST_DIR)/$(APP_NAME)-$(APP_VERSION)-$(ARCHIVE_FLAVOR).zip"
	/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$(APP_BUNDLE)" "$(DIST_DIR)/$(APP_NAME)-$(APP_VERSION)-$(ARCHIVE_FLAVOR).zip"

clean:
	swift package clean
	rm -rf "$(DIST_DIR)" Resources/Hajimi.icns Resources/Hajimi.iconset
