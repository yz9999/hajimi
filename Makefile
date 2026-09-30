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

.PHONY: all native-core build app icon clean run test test-native test-icons test-rules test-cpp test-quic test-chains network-extension verify archive

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

all: app

native-core:
	HAJIMI_ARCHS="$(ARCHS)" ./scripts/build_native_core.sh

build: native-core
	swift build -c $(BUILD_CONFIG) $(SWIFT_ARCH_FLAGS)

icon:
	python3 scripts/generate_icon.py

test-icons: icon
	mkdir -p .build/icon-tests
	xcrun swiftc -target $(shell uname -m)-apple-macos13.0 -framework AppKit Sources/HajimiApp/StatusBarCatIcon.swift Sources/HajimiApp/HajimiBrandIcon.swift SmokeTests/IconAssetsMain.swift -o .build/icon-tests/icon-check
	.build/icon-tests/icon-check Resources

test-rules:
	mkdir -p "$(RULE_TEST_DIR)"
	xcrun swiftc $(RULE_TEST_FLAGS) Sources/HajimiCore/Profile.swift Sources/HajimiCore/SurgeProfileDocument.swift Sources/HajimiApp/RuleTableSelection.swift SmokeTests/RuleEditingMain.swift -o "$(RULE_TEST_DIR)/rule-editing-check"
	"$(RULE_TEST_DIR)/rule-editing-check"
	xcrun swiftc $(RULE_TEST_FLAGS) Sources/HajimiApp/ProfileApplyCommitGuard.swift SmokeTests/RuleCommitGuardMain.swift -o "$(RULE_TEST_DIR)/rule-commit-guard-check"
	"$(RULE_TEST_DIR)/rule-commit-guard-check"
	xcrun swiftc $(RULE_TEST_FLAGS) -parse-as-library -emit-module -emit-library -module-name HajimiCore Sources/HajimiCore/Profile.swift Sources/HajimiCore/SurgeProfileDocument.swift -emit-module-path "$(RULE_TEST_DIR)/HajimiCore.swiftmodule" -Xlinker -install_name -Xlinker '@rpath/libHajimiCore.dylib' -o "$(RULE_TEST_DIR)/libHajimiCore.dylib"
	xcrun swiftc $(RULE_TEST_FLAGS) -I "$(RULE_TEST_DIR)" -L "$(RULE_TEST_DIR)" -lHajimiCore -Xlinker -rpath -Xlinker "$(CURDIR)/$(RULE_TEST_DIR)" Sources/HajimiApp/SurgeRuleSetManager.swift SmokeTests/RuleSetRefreshMain.swift -o "$(RULE_TEST_DIR)/rule-refresh-check"
	"$(RULE_TEST_DIR)/rule-refresh-check"
	xcrun swiftc $(RULE_TEST_FLAGS) -framework AppKit -I "$(RULE_TEST_DIR)" -L "$(RULE_TEST_DIR)" -lHajimiCore -Xlinker -rpath -Xlinker "$(CURDIR)/$(RULE_TEST_DIR)" Sources/HajimiApp/RuleUIComponents.swift SmokeTests/RuleEditorUIMain.swift -o "$(RULE_TEST_DIR)/rule-editor-ui-check"
	"$(RULE_TEST_DIR)/rule-editor-ui-check"

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

test-quic: native-core
	sh scripts/test_cpp_quic.sh

test-chains: build
	python3 SmokeTests/live_proxy_chains.py --binary "$(BUILD_DIR)/$(EXECUTABLE_NAME)"
	python3 SmokeTests/live_proxies.py --binary "$(BUILD_DIR)/$(EXECUTABLE_NAME)"

test-native: test-cpp
	sh scripts/test_cpp_quic_boundaries.sh
	mkdir -p .build/smoke-tests
	clang++ -std=c++17 -O2 -Wall -Wextra -Werror -I Sources/HajimiFlowCXX/include Sources/HajimiFlowCXX/FlowState.cpp SmokeTests/FlowStateMain.cpp -o .build/smoke-tests/flow-check
	.build/smoke-tests/flow-check
	clang++ -std=c++17 -O2 -fno-exceptions -fno-rtti -Wall -Wextra -Werror -I Sources/HajimiProtocolCXX/include Sources/HajimiProtocolCXX/ProtocolCodec.cpp SmokeTests/ProtocolCodecMain.cpp -o .build/smoke-tests/protocol-codec-check
	.build/smoke-tests/protocol-codec-check
	clang++ -std=c++17 -O2 -fobjc-arc -fblocks -Wall -Wextra -Werror -I Sources/HajimiProxyRuntime/include Sources/HajimiProxyRuntime/HajimiProxyRuntime.mm SmokeTests/NativeRuntimeMain.mm -framework Foundation -framework Network -framework Security -o .build/smoke-tests/native-runtime-check
	.build/smoke-tests/native-runtime-check
	clang -O2 -fobjc-arc -fblocks -Wall -Wextra -Werror -I Sources/HajimiMacOSObjC/include Sources/HajimiMacOSObjC/HJNetworkExtensionController.m Sources/HajimiMacOSObjC/HJTrafficDashboardView.m SmokeTests/MacOSIntegrationMain.m -framework Foundation -framework AppKit -framework NetworkExtension -framework Security -o .build/smoke-tests/macos-integration-check
	.build/smoke-tests/macos-integration-check

network-extension:
	sh NetworkExtension/build-provider.sh

test: build test-native test-chains test-icons test-rules
	mkdir -p .build/smoke-tests
	swiftc Sources/HajimiCore/Profile.swift Sources/HajimiCore/SurgeProfileDocument.swift SmokeTests/main.swift -o .build/smoke-tests/profile-check
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
	@! /usr/bin/nm "$(APP_BUNDLE)/Contents/MacOS/$(EXECUTABLE_NAME)" | rg '(_runtime\.|_cgo_|_crosscall|_LurgeQUIC|_x_cgo_)' || { echo "Unexpected legacy Go bridge/runtime symbols"; exit 1; }
	$(TEST_ENV) "$(APP_BUNDLE)/Contents/MacOS/$(EXECUTABLE_NAME)" --ingress-security-self-test
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
