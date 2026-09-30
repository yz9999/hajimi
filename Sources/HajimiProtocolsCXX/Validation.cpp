#include "Runtime.hpp"
#include "BasicProtocols.hpp"
#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace hajimi {
// Advanced protocol implementations own their option/cipher validation.
Error validateAnyTLS(const Node &,bool);
Error validateSnell(const Node &,bool);
Error validateSSH(const Node &,bool);
static std::string lower(std::string value) {
    std::transform(value.begin(),value.end(),value.begin(),[](unsigned char ch){return char(std::tolower(ch));});return value;
}
static bool validBoolean(const std::string &input) {
    auto value=lower(input); value.erase(std::remove_if(value.begin(),value.end(),[](unsigned char ch){return std::isspace(ch);}),value.end());
    return value=="true" || value=="yes" || value=="on" || value=="1" || value=="false" || value=="no" || value=="off" || value=="0";
}
Error validateBasicProtocol(const Node &node,bool udp) {
    if(node.type=="http" || node.type=="https") {
        if(udp)return "HTTP proxies do not support UDP relay";
        if(node.option("username").size()>4096 || node.option("password").size()>4096)return "HTTP proxy credential limit exceeded";
        auto tls=tlsOptions(node,node.type=="https");
        if(node.type=="https" && !tls.enabled)return "HTTPS cannot disable TLS";
        if(!tls.enabled && !tls.alpn.empty())return "Cleartext HTTP cannot configure TLS ALPN";
        for(auto &alpn:tls.alpn)if(alpn!="http/1.1")return "HTTPS proxy requires HTTP/1.1 ALPN";
        return {};
    }
    if(node.type=="socks5" || node.type=="socks5-tls") {
        if(udp && tlsOptions(node,node.type=="socks5-tls").enabled)return "SOCKS5-TLS does not encrypt the RFC1928 UDP relay; plaintext UDP refused";
        if(node.type=="socks5-tls" && !tlsOptions(node,true).enabled)return "SOCKS5-TLS cannot disable TLS";
        if(node.parameters.count("username") && (node.option("username").empty() || node.option("username").size()>255 || node.option("password").size()>255))return "Invalid SOCKS5 credential lengths";
        if(!tlsOptions(node,node.type=="socks5-tls").enabled && !node.option("alpn").empty())return "Cleartext SOCKS5 cannot configure TLS ALPN";
        return {};
    }
    if(node.type=="vmess" || node.type=="vless") {
        try { uuidBytes(node.option("uuid",node.option("username"))); } catch(const std::exception &e){return e.what();}
        if(node.type=="vmess") {
            if(!node.flag("vmess-aead",true))return "VMess requires AEAD authentication";
            auto alter=node.option("alter-id",node.option("alterid","0"));if(alter!="0")return "Legacy VMess alter-id is not supported";
            auto cipher=lower(node.option("cipher",node.option("encryption","auto")));
            if(cipher!="auto" && cipher!="aes-128-gcm")return "VMess currently requires AES-128-GCM body encryption";
        } else {
            auto encryption=lower(node.option("encryption","none"));if(!encryption.empty() && encryption!="none")return "Unsupported VLESS encryption extension";
            auto flow=lower(node.option("flow"));
            if(!flow.empty() && flow!="xtls-rprx-vision" && flow!="xtls-rprx-vision-udp443")return "Unsupported VLESS flow";
            if(!flow.empty()) {
                bool reality=node.parameters.count("reality-public-key") || lower(node.option("security"))=="reality";
                auto network=lower(node.option("network","tcp"));
                if(!reality || (network!="tcp" && !network.empty()))return "VLESS Vision requires REALITY over TCP";
                if(node.flag("mux"))return "VLESS Vision TCP cannot use shared Mux.Cool";
                // The datagram entry point uses command=mux/XUDP, not command=2.
                if(udp)return "VLESS Vision UDP requires an XUDP carrier";
            }
        }
        if(node.flag("global-padding") || node.flag("authenticated-length"))return "Unsupported VMess/VLESS framing option";
        return {};
    }
    if(node.type=="trojan") {
        if(node.option("password").empty())return "Missing Trojan password";
        return {};
    }
    if(node.type=="direct")return udp ? "DIRECT uses the platform datagram transport" : Error{};
    return "Unknown C++ proxy protocol";
}
Error validateProtocol(const Node &node,bool udp) {
    if(node.host.empty() || !node.port || node.host.find('\0')!=std::string::npos)return "Missing or invalid proxy endpoint";
    for(auto &key:{"tls","skip-cert-verify","skip-common-name-verify"}) {
        auto found=node.parameters.find(key);if(found!=node.parameters.end() && !validBoolean(found->second))return "Invalid TLS boolean option";
    }
    if(lower(node.option("security"))=="tls" && !node.flag("tls",true))return "security=tls cannot disable TLS";
    if(node.flag("skip-common-name-verify") && !node.flag("skip-cert-verify"))return "Partial TLS hostname bypass is not supported; certificate verification remains required";
    bool chain=!node.option("underlying-proxy",node.option("dialer-proxy")).empty();
    if(udp && chain && (node.type=="ss" || node.type=="ssr" || node.type=="socks5" || node.type=="socks5-tls"))return "UDP over this proxy chain is not supported; direct relay bypass refused";
    if(node.type=="ss" || node.type=="ssr")return validateShadowsocks(node,udp);
    if(node.type=="anytls")return validateAnyTLS(node,udp);
    if(node.type=="snell")return validateSnell(node,udp);
    if(node.type=="ssh")return validateSSH(node,udp);
    if(node.type=="hysteria" || node.type=="hysteria2" || node.type=="tuic")return validateQUICProtocol(node,udp);
    return validateBasicProtocol(node,udp);
}
} // namespace hajimi
