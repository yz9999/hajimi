// Sudoku Protocol Codec, Key Schedule, O(1) 4x4 Puzzle Table & KIP Framing
#include "SudokuCodec.hpp"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <mutex>
#include <unordered_map>

namespace hajimi::sudoku_detail {

// ============================================================================
// 1. SUDOKU PROTOCOL (Official SUDOKU-ASCII/sudoku v0.5.2 Wire Specification)
// ============================================================================


bool isValidCustomTablePattern(const std::string &pattern) {
    if (pattern.size() != 8) return false;
    int xCount = 0, pCount = 0, vCount = 0;
    for (char c : pattern) {
        if (c == 'x') ++xCount;
        else if (c == 'p') ++pCount;
        else if (c == 'v') ++vCount;
        else return false;
    }
    return xCount == 2 && pCount == 2 && vCount == 4;
}

Error parseSudokuConfig(const Node &node, SudokuConfig &cfg) {
    cfg.key = trimAscii(node.option("key", node.option("password")));
    if (cfg.key.empty()) return "Sudoku requires a non-empty key";
    if (cfg.key.size() > 4096) return "Sudoku key exceeds maximum length";

    cfg.aeadMethod = lowerAscii(node.option("aead-method", node.option("cipher", "chacha20-poly1305")));
    if (cfg.aeadMethod != "chacha20-poly1305" &&
        cfg.aeadMethod != "aes-128-gcm" &&
        cfg.aeadMethod != "none") {
        return "Sudoku aead-method must be chacha20-poly1305, aes-128-gcm, or none";
    }

    cfg.tableType = lowerAscii(node.option("table-type", node.option("ascii", "prefer_ascii")));
    if (cfg.tableType == "ascii") cfg.tableType = "prefer_ascii";
    else if (cfg.tableType == "entropy") cfg.tableType = "prefer_entropy";
    if (cfg.tableType != "prefer_ascii" &&
        cfg.tableType != "prefer_entropy" &&
        cfg.tableType != "up_ascii_down_entropy" &&
        cfg.tableType != "up_entropy_down_ascii") {
        return "Sudoku table-type must be prefer_ascii, prefer_entropy, up_ascii_down_entropy, or up_entropy_down_ascii";
    }

    cfg.customTable = lowerAscii(node.option("custom-table"));
    if (cfg.customTable.empty()) {
        std::string tables = lowerAscii(node.option("custom-tables"));
        if (!tables.empty()) {
            auto sep = tables.find_first_of(";, ");
            cfg.customTable = (sep == std::string::npos) ? tables : tables.substr(0, sep);
        }
    }
    if (!cfg.customTable.empty() && !isValidCustomTablePattern(cfg.customTable)) {
        return "Sudoku custom-table must contain 2 'x', 2 'p', and 4 'v' bits";
    }

    auto pminStr = node.option("padding-min", "2");
    auto pmaxStr = node.option("padding-max", "7");
    if (!parseUint32(pminStr, 0, 100, cfg.paddingMin) ||
        !parseUint32(pmaxStr, 0, 100, cfg.paddingMax) ||
        cfg.paddingMin > cfg.paddingMax) {
        return "Sudoku padding-min/padding-max must be between 0 and 100 with min <= max";
    }

    if (node.parameters.count("enable-pure-downlink")) {
        cfg.enablePureDownlink = node.flag("enable-pure-downlink", true);
    } else if (node.parameters.count("packed-downlink") || node.parameters.count("x")) {
        cfg.enablePureDownlink = !node.flag("packed-downlink", node.flag("x", false));
    } else {
        cfg.enablePureDownlink = true;
    }
    bool explicitMask = node.flag("http-mask", true);
    cfg.disableHttpMask = node.flag("disable-http-mask", !explicitMask);
    cfg.httpMaskMode = lowerAscii(node.option("http-mask-mode", "auto"));
    if (cfg.httpMaskMode != "legacy" && cfg.httpMaskMode != "stream" &&
        cfg.httpMaskMode != "poll" && cfg.httpMaskMode != "auto" &&
        cfg.httpMaskMode != "ws") {
        return "Sudoku http-mask-mode must be legacy, stream, poll, auto, or ws";
    }
    cfg.httpMaskTls = node.flag("http-mask-tls", node.flag("tls", false));
    cfg.httpMaskHost = node.option("http-mask-host", node.host);
    cfg.pathRoot = node.option("path-root");
    cfg.multiplex = lowerAscii(node.option("multiplex", node.option("http-mask-multiplex", "off")));
    if (cfg.multiplex != "off" && cfg.multiplex != "auto" && cfg.multiplex != "on" &&
        cfg.multiplex != "false" && cfg.multiplex != "true") {
        return "Sudoku multiplex must be off, auto, or on";
    }
    return {};
}

// Edwards25519 scalar basepoint multiplication for SUDOKU-ASCII/sudoku Split Private Key -> Master Public Key
bool sudokuRecoverMasterPublicKey(const std::string &keyHex, std::string &outMasterPubHex, Buffer &outUserHash8) {
    std::string trimmed = trimAscii(keyHex);
    struct CachedMasterKey {
        std::string masterPubHex;
        Buffer userHash8;
        bool ok = false;
    };
    static std::mutex recoverCacheMutex;
    static std::unordered_map<std::string, CachedMasterKey> recoverCache;
    {
        std::lock_guard<std::mutex> lock(recoverCacheMutex);
        auto it = recoverCache.find(trimmed);
        if (it != recoverCache.end()) {
            outMasterPubHex = it->second.masterPubHex;
            outUserHash8 = it->second.userHash8;
            return it->second.ok;
        }
        if (recoverCache.size() > 64) recoverCache.clear();
    }
    auto storeAndReturn = [&](bool ok) -> bool {
        std::lock_guard<std::mutex> lock(recoverCacheMutex);
        recoverCache[trimmed] = CachedMasterKey{outMasterPubHex, outUserHash8, ok};
        return ok;
    };
    Buffer raw;
    if (decodeHexBytes(trimmed, raw) && (raw.size() == 32 || raw.size() == 64)) {
        Buffer d = crypto::digest("SHA256", raw);
        outUserHash8.assign(d.begin(), d.begin() + 8);
    } else {
        Buffer kb(trimmed.begin(), trimmed.end());
        Buffer d = crypto::digest("SHA256", kb);
        outUserHash8.assign(d.begin(), d.begin() + 8);
        outMasterPubHex = trimmed;
        return false;
    }

    using BnCtxPtr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
    BnCtxPtr ctx(BN_CTX_new(), BN_CTX_free);
    if (!ctx) { outMasterPubHex = lowerAscii(trimmed); return false; }
    BN_CTX_start(ctx.get());

    // Group order L = 2^252 + 27742317777372353535851937790883648493 (big-endian)
    static const uint8_t kOrderL_BE[32] = {
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6,
        0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed
    };
    // Prime p = 2^255 - 19 (big-endian)
    static const uint8_t kPrimeP_BE[32] = {
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed
    };
    // Basepoint Bx (big-endian)
    static const uint8_t kBaseX_BE[32] = {
        0x21, 0x69, 0x36, 0xd3, 0xcd, 0x6e, 0x53, 0xfe,
        0xc0, 0xa4, 0xe2, 0x31, 0xfd, 0xd6, 0xdc, 0x5c,
        0x69, 0x2c, 0xc7, 0x60, 0x95, 0x25, 0xa7, 0xb2,
        0xc9, 0x56, 0x2d, 0x60, 0x8f, 0x25, 0xd5, 0x1a
    };
    // Basepoint By = 4/5 mod p (big-endian)
    static const uint8_t kBaseY_BE[32] = {
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x58
    };
    // Curve constant d = -121665/121666 mod p (big-endian)
    static const uint8_t kConstD_BE[32] = {
        0x52, 0x03, 0x6c, 0xee, 0x2b, 0x6f, 0xfe, 0x73,
        0x8c, 0xc7, 0x40, 0x79, 0x77, 0x79, 0xe8, 0x98,
        0x00, 0x70, 0x0a, 0x4d, 0x41, 0x41, 0xd8, 0xab,
        0x75, 0xeb, 0x4d, 0xca, 0x13, 0x59, 0x78, 0xa3
    };

    BIGNUM *L = BN_CTX_get(ctx.get());
    BIGNUM *x = BN_CTX_get(ctx.get());
    BIGNUM *r = BN_CTX_get(ctx.get());
    BIGNUM *k = BN_CTX_get(ctx.get());
    BN_bin2bn(kOrderL_BE, 32, L);

    if (raw.size() == 64) {
        BN_lebin2bn(raw.data(), 32, r);
        BN_lebin2bn(raw.data() + 32, 32, k);
        if (BN_cmp(r, L) >= 0 || BN_cmp(k, L) >= 0) {
            BN_CTX_end(ctx.get());
            outMasterPubHex = lowerAscii(trimmed);
            return false;
        }
        BN_mod_add(x, r, k, L, ctx.get());
    } else {
        BN_lebin2bn(raw.data(), 32, x);
        if (BN_cmp(x, L) >= 0 || BN_is_zero(x)) {
            BN_CTX_end(ctx.get());
            outMasterPubHex = lowerAscii(trimmed);
            return false;
        }
    }
    if (BN_is_zero(x)) {
        BN_CTX_end(ctx.get());
        outMasterPubHex = lowerAscii(trimmed);
        return false;
    }

    BIGNUM *p = BN_CTX_get(ctx.get());
    BIGNUM *d = BN_CTX_get(ctx.get());
    BIGNUM *d2 = BN_CTX_get(ctx.get());
    BN_bin2bn(kPrimeP_BE, 32, p);
    BN_bin2bn(kConstD_BE, 32, d);
    BN_mod_add(d2, d, d, p, ctx.get());

    struct EdPoint { BIGNUM *X, *Y, *Z, *T; };
    auto allocPt = [&]() -> EdPoint {
        return {BN_CTX_get(ctx.get()), BN_CTX_get(ctx.get()), BN_CTX_get(ctx.get()), BN_CTX_get(ctx.get())};
    };
    EdPoint res = allocPt();
    BN_zero(res.X); BN_one(res.Y); BN_one(res.Z); BN_zero(res.T);

    EdPoint base = allocPt();
    BN_bin2bn(kBaseX_BE, 32, base.X);
    BN_bin2bn(kBaseY_BE, 32, base.Y);
    BN_one(base.Z);
    BN_mod_mul(base.T, base.X, base.Y, p, ctx.get());

    BIGNUM *A = BN_CTX_get(ctx.get());
    BIGNUM *B = BN_CTX_get(ctx.get());
    BIGNUM *C = BN_CTX_get(ctx.get());
    BIGNUM *D = BN_CTX_get(ctx.get());
    BIGNUM *E = BN_CTX_get(ctx.get());
    BIGNUM *F = BN_CTX_get(ctx.get());
    BIGNUM *G = BN_CTX_get(ctx.get());
    BIGNUM *H = BN_CTX_get(ctx.get());
    BIGNUM *t1 = BN_CTX_get(ctx.get());
    BIGNUM *t2 = BN_CTX_get(ctx.get());

    auto edAdd = [&](EdPoint &dst, const EdPoint &P, const EdPoint &Q) {
        BN_mod_sub(t1, P.Y, P.X, p, ctx.get());
        BN_mod_sub(t2, Q.Y, Q.X, p, ctx.get());
        BN_mod_mul(A, t1, t2, p, ctx.get());

        BN_mod_add(t1, P.Y, P.X, p, ctx.get());
        BN_mod_add(t2, Q.Y, Q.X, p, ctx.get());
        BN_mod_mul(B, t1, t2, p, ctx.get());

        BN_mod_mul(t1, P.T, Q.T, p, ctx.get());
        BN_mod_mul(C, d2, t1, p, ctx.get());

        BN_mod_mul(t1, P.Z, Q.Z, p, ctx.get());
        BN_mod_add(D, t1, t1, p, ctx.get());

        BN_mod_sub(E, B, A, p, ctx.get());
        BN_mod_sub(F, D, C, p, ctx.get());
        BN_mod_add(G, D, C, p, ctx.get());
        BN_mod_add(H, B, A, p, ctx.get());

        BN_mod_mul(dst.X, E, F, p, ctx.get());
        BN_mod_mul(dst.Y, G, H, p, ctx.get());
        BN_mod_mul(dst.Z, F, G, p, ctx.get());
        BN_mod_mul(dst.T, E, H, p, ctx.get());
    };

    int numBits = BN_num_bits(x);
    for (int bit = 0; bit < numBits; ++bit) {
        if (BN_is_bit_set(x, bit)) {
            edAdd(res, res, base);
        }
        edAdd(base, base, base);
    }

    BIGNUM *zi = BN_CTX_get(ctx.get());
    BIGNUM *affX = BN_CTX_get(ctx.get());
    BIGNUM *affY = BN_CTX_get(ctx.get());
    BN_mod_inverse(zi, res.Z, p, ctx.get());
    BN_mod_mul(affX, res.X, zi, p, ctx.get());
    BN_mod_mul(affY, res.Y, zi, p, ctx.get());

    Buffer pubBytes(32, 0);
    BN_bn2lebinpad(affY, pubBytes.data(), 32);
    if (BN_is_odd(affX)) {
        pubBytes[31] |= 0x80;
    }
    BN_CTX_end(ctx.get());
    outMasterPubHex = encodeHexLower(pubBytes);
    return storeAndReturn(true);
}

// Go standard library math/rand additive lagged Fibonacci generator (Mitchell & Reeds)
class GoRng {
public:
    explicit GoRng(int64_t seed) { seedRng(seed); }

    uint64_t uint64Val() {
        tap_--;
        if (tap_ < 0) tap_ += kRngLen;
        feed_--;
        if (feed_ < 0) feed_ += kRngLen;
        int64_t x = int64_t(uint64_t(vec_[feed_]) + uint64_t(vec_[tap_]));
        vec_[feed_] = x;
        return uint64_t(x);
    }

    int64_t int63Val() {
        return int64_t(uint64_ValMask());
    }

    uint32_t uint32Val() {
        return uint32_t(int63Val() >> 31);
    }

    // Matches Go math/rand/rand.go unexported Rand.int31n(n) called by Rand.Shuffle
    int32_t int31n(int32_t n) {
        uint32_t un = uint32_t(n);
        uint32_t v = uint32Val();
        uint64_t prod = uint64_t(v) * uint64_t(un);
        uint32_t low = uint32_t(prod);
        if (low < un) {
            uint32_t thresh = (0u - un) % un;
            while (low < thresh) {
                v = uint32Val();
                prod = uint64_t(v) * uint64_t(un);
                low = uint32_t(prod);
            }
        }
        return int32_t(prod >> 32);
    }

private:
    static constexpr int kRngLen = 607;
    static constexpr int kRngTap = 273;
    static constexpr uint64_t kRngMask = (1ULL << 63) - 1;
    static constexpr int32_t kInt32Max = (1U << 31) - 1;

    uint64_t uint64_ValMask() { return uint64Val() & kRngMask; }

    static int32_t seedrand(int32_t x) {
        constexpr int32_t A = 48271;
        constexpr int32_t Q = 44488;
        constexpr int32_t R = 3399;
        int32_t hi = x / Q;
        int32_t lo = x % Q;
        x = A * lo - R * hi;
        if (x < 0) x += kInt32Max;
        return x;
    }

    void seedRng(int64_t seed) {
        static const int64_t kRngCooked[kRngLen] = {
            -4181792142133755926LL, -4576982950128230565LL, 1395769623340756751LL, 5333664234075297259LL,
            -6347679516498800754LL, 9033628115061424579LL, 7143218595135194537LL, 4812947590706362721LL,
            7937252194349799378LL, 5307299880338848416LL, 8209348851763925077LL, -7107630437535961764LL,
            4593015457530856296LL, 8140875735541888011LL, -5903942795589686782LL, -603556388664454774LL,
            -7496297993371156308LL, 113108499721038619LL, 4569519971459345583LL, -4160538177779461077LL,
            -6835753265595711384LL, -6507240692498089696LL, 6559392774825876886LL, 7650093201692370310LL,
            7684323884043752161LL, -8965504200858744418LL, -2629915517445760644LL, 271327514973697897LL,
            -6433985589514657524LL, 1065192797246149621LL, 3344507881999356393LL, -4763574095074709175LL,
            7465081662728599889LL, 1014950805555097187LL, -4773931307508785033LL, -5742262670416273165LL,
            2418672789110888383LL, 5796562887576294778LL, 4484266064449540171LL, 3738982361971787048LL,
            -4699774852342421385LL, 10530508058128498LL, -589538253572429690LL, -6598062107225984180LL,
            8660405965245884302LL, 10162832508971942LL, -2682657355892958417LL, 7031802312784620857LL,
            6240911277345944669LL, 831864355460801054LL, -1218937899312622917LL, 2116287251661052151LL,
            2202309800992166967LL, 9161020366945053561LL, 4069299552407763864LL, 4936383537992622449LL,
            457351505131524928LL, -8881176990926596454LL, -6375600354038175299LL, -7155351920868399290LL,
            4368649989588021065LL, 887231587095185257LL, -3659780529968199312LL, -2407146836602825512LL,
            5616972787034086048LL, -751562733459939242LL, 1686575021641186857LL, -5177887698780513806LL,
            -4979215821652996885LL, -1375154703071198421LL, 5632136521049761902LL, -8390088894796940536LL,
            -193645528485698615LL, -5979788902190688516LL, -4907000935050298721LL, -285522056888777828LL,
            -2776431630044341707LL, 1679342092332374735LL, 6050638460742422078LL, -2229851317345194226LL,
            -1582494184340482199LL, 5881353426285907985LL, 812786550756860885LL, 4541845584483343330LL,
            -6497901820577766722LL, 4980675660146853729LL, -4012602956251539747LL, -329088717864244987LL,
            -2896929232104691526LL, 1495812843684243920LL, -2153620458055647789LL, 7370257291860230865LL,
            -2466442761497833547LL, 4706794511633873654LL, -1398851569026877145LL, 8549875090542453214LL,
            -9189721207376179652LL, -7894453601103453165LL, 7297902601803624459LL, 1011190183918857495LL,
            -6985347000036920864LL, 5147159997473910359LL, -8326859945294252826LL, 2659470849286379941LL,
            6097729358393448602LL, -7491646050550022124LL, -5117116194870963097LL, -896216826133240300LL,
            -745860416168701406LL, 5803876044675762232LL, -787954255994554146LL, -3234519180203704564LL,
            -4507534739750823898LL, -1657200065590290694LL, 505808562678895611LL, -4153273856159712438LL,
            -8381261370078904295LL, 572156825025677802LL, 1791881013492340891LL, 3393267094866038768LL,
            -5444650186382539299LL, 2352769483186201278LL, -7930912453007408350LL, -325464993179687389LL,
            -3441562999710612272LL, -6489413242825283295LL, 5092019688680754699LL, -227247482082248967LL,
            4234737173186232084LL, 5027558287275472836LL, 4635198586344772304LL, -536033143587636457LL,
            5907508150730407386LL, -8438615781380831356LL, 972392927514829904LL, -3801314342046600696LL,
            -4064951393885491917LL, -174840358296132583LL, 2407211146698877100LL, -1640089820333676239LL,
            3940796514530962282LL, -5882197405809569433LL, 3095313889586102949LL, -1818050141166537098LL,
            5832080132947175283LL, 7890064875145919662LL, 8184139210799583195LL, -8073512175445549678LL,
            -7758774793014564506LL, -4581724029666783935LL, 3516491885471466898LL, -8267083515063118116LL,
            6657089965014657519LL, 5220884358887979358LL, 1796677326474620641LL, 5340761970648932916LL,
            1147977171614181568LL, 5066037465548252321LL, 2574765911837859848LL, 1085848279845204775LL,
            -5873264506986385449LL, 6116438694366558490LL, 2107701075971293812LL, -7420077970933506541LL,
            2469478054175558874LL, -1855128755834809824LL, -5431463669011098282LL, -9038325065738319171LL,
            -6966276280341336160LL, 7217693971077460129LL, -8314322083775271549LL, 7196649268545224266LL,
            -3585711691453906209LL, -5267827091426810625LL, 8057528650917418961LL, -5084103596553648165LL,
            -2601445448341207749LL, -7850010900052094367LL, 6527366231383600011LL, 3507654575162700890LL,
            9202058512774729859LL, 1954818376891585542LL, -2582991129724600103LL, 8299563319178235687LL,
            -5321504681635821435LL, 7046310742295574065LL, -2376176645520785576LL, -7650733936335907755LL,
            8850422670118399721LL, 3631909142291992901LL, 5158881091950831288LL, -6340413719511654215LL,
            4763258931815816403LL, 6280052734341785344LL, -4979582628649810958LL, 2043464728020827976LL,
            -2678071570832690343LL, 4562580375758598164LL, 5495451168795427352LL, -7485059175264624713LL,
            553004618757816492LL, 6895160632757959823LL, -989748114590090637LL, 7139506338801360852LL,
            -672480814466784139LL, 5535668688139305547LL, 2430933853350256242LL, -3821430778991574732LL,
            -1063731997747047009LL, -3065878205254005442LL, 7632066283658143750LL, 6308328381617103346LL,
            3681878764086140361LL, 3289686137190109749LL, 6587997200611086848LL, 244714774258135476LL,
            -5143583659437639708LL, 8090302575944624335LL, 2945117363431356361LL, -8359047641006034763LL,
            3009039260312620700LL, -793344576772241777LL, 401084700045993341LL, -1968749590416080887LL,
            4707864159563588614LL, -3583123505891281857LL, -3240864324164777915LL, -5908273794572565703LL,
            -3719524458082857382LL, -5281400669679581926LL, 8118566580304798074LL, 3839261274019871296LL,
            7062410411742090847LL, -8481991033874568140LL, 6027994129690250817LL, -6725542042704711878LL,
            -2971981702428546974LL, -7854441788951256975LL, 8809096399316380241LL, 6492004350391900708LL,
            2462145737463489636LL, -8818543617934476634LL, -5070345602623085213LL, -8961586321599299868LL,
            -3758656652254704451LL, -8630661632476012791LL, 6764129236657751224LL, -709716318315418359LL,
            -3403028373052861600LL, -8838073512170985897LL, -3999237033416576341LL, -2920240395515973663LL,
            -2073249475545404416LL, 368107899140673753LL, -6108185202296464250LL, -6307735683270494757LL,
            4782583894627718279LL, 6718292300699989587LL, 8387085186914375220LL, 3387513132024756289LL,
            4654329375432538231LL, -292704475491394206LL, -3848998599978456535LL, 7623042350483453954LL,
            7725442901813263321LL, 9186225467561587250LL, -5132344747257272453LL, -6865740430362196008LL,
            2530936820058611833LL, 1636551876240043639LL, -3658707362519810009LL, 1452244145334316253LL,
            -7161729655835084979LL, -7943791770359481772LL, 9108481583171221009LL, -3200093350120725999LL,
            5007630032676973346LL, 2153168792952589781LL, 6720334534964750538LL, -3181825545719981703LL,
            3433922409283786309LL, 2285479922797300912LL, 3110614940896576130LL, -2856812446131932915LL,
            -3804580617188639299LL, 7163298419643543757LL, 4891138053923696990LL, 580618510277907015LL,
            1684034065251686769LL, 4429514767357295841LL, -8893025458299325803LL, -8103734041042601133LL,
            7177515271653460134LL, 4589042248470800257LL, -1530083407795771245LL, 143607045258444228LL,
            246994305896273627LL, -8356954712051676521LL, 6473547110565816071LL, 3092379936208876896LL,
            2058427839513754051LL, -4089587328327907870LL, 8785882556301281247LL, -3074039370013608197LL,
            -637529855400303673LL, 6137678347805511274LL, -7152924852417805802LL, 5708223427705576541LL,
            -3223714144396531304LL, 4358391411789012426LL, 325123008708389849LL, 6837621693887290924LL,
            4843721905315627004LL, -3212720814705499393LL, -3825019837890901156LL, 4602025990114250980LL,
            1044646352569048800LL, 9106614159853161675LL, -8394115921626182539LL, -4304087667751778808LL,
            2681532557646850893LL, 3681559472488511871LL, -3915372517896561773LL, -2889241648411946534LL,
            -6564663803938238204LL, -8060058171802589521LL, 581945337509520675LL, 3648778920718647903LL,
            -4799698790548231394LL, -7602572252857820065LL, 220828013409515943LL, -1072987336855386047LL,
            4287360518296753003LL, -4633371852008891965LL, 5513660857261085186LL, -0x1f582907cb4bf3bdLL,
            -8744380348503999773LL, 8746140185685648781LL, 228500091334420247LL, 1356187007457302238LL,
            3019253992034194581LL, 3152601605678500003LL, -8793219284148773595LL, 5559581553696971176LL,
            4916432985369275664LL, -8559797105120221417LL, -5802598197927043732LL, 2868348622579915573LL,
            -7224052902810357288LL, -5894682518218493085LL, 2587672709781371173LL, -7706116723325376475LL,
            3092343956317362483LL, -5561119517847711700LL, 972445599196498113LL, -1558506600978816441LL,
            1708913533482282562LL, -2305554874185907314LL, -6005743014309462908LL, -6653329009633068701LL,
            -483583197311151195LL, 2488075924621352812LL, -4529369641467339140LL, -4663743555056261452LL,
            2997203966153298104LL, 1282559373026354493LL, 240113143146674385LL, 8665713329246516443LL,
            628141331766346752LL, -4651421219668005332LL, -7750560848702540400LL, 7596648026010355826LL,
            -3132152619100351065LL, 7834161864828164065LL, 7103445518877254909LL, 4390861237357459201LL,
            -4780718172614204074LL, -319889632007444440LL, 622261699494173647LL, -3186110786557562560LL,
            -8718967088789066690LL, -1948156510637662747LL, -8212195255998774408LL, -7028621931231314745LL,
            2623071828615234808LL, -4066058308780939700LL, -5484966924888173764LL, -6683604512778046238LL,
            -6756087640505506466LL, 5256026990536851868LL, 7841086888628396109LL, 6640857538655893162LL,
            -8021284697816458310LL, -7109857044414059830LL, -1689021141511844405LL, -4298087301956291063LL,
            -4077748265377282003LL, -998231156719803476LL, 2719520354384050532LL, 9132346697815513771LL,
            4332154495710163773LL, -2085582442760428892LL, 6994721091344268833LL, -2556143461985726874LL,
            -8567931991128098309LL, 59934747298466858LL, -3098398008776739403LL, -265597256199410390LL,
            2332206071942466437LL, -7522315324568406181LL, 3154897383618636503LL, -7585605855467168281LL,
            -6762850759087199275LL, 197309393502684135LL, -8579694182469508493LL, 2543179307861934850LL,
            4350769010207485119LL, -4468719947444108136LL, -7207776534213261296LL, -1224312577878317200LL,
            4287946071480840813LL, 8362686366770308971LL, 6486469209321732151LL, -5605644191012979782LL,
            -1669018511020473564LL, 4450022655153542367LL, -7618176296641240059LL, -3896357471549267421LL,
            -4596796223304447488LL, -6531150016257070659LL, -8982326463137525940LL, -4125325062227681798LL,
            -1306489741394045544LL, -8338554946557245229LL, 5329160409530630596LL, 7790979528857726136LL,
            4955070238059373407LL, -4304834761432101506LL, -6215295852904371179LL, 3007769226071157901LL,
            -6753025801236972788LL, 8928702772696731736LL, 7856187920214445904LL, -4748497451462800923LL,
            7900176660600710914LL, -7082800908938549136LL, -6797926979589575837LL, -6737316883512927978LL,
            4186670094382025798LL, 1883939007446035042LL, -414705992779907823LL, 3734134241178479257LL,
            4065968871360089196LL, 6953124200385847784LL, -7917685222115876751LL, -7585632937840318161LL,
            -5567246375906782599LL, -5256612402221608788LL, 3106378204088556331LL, -2894472214076325998LL,
            4565385105440252958LL, 1979884289539493806LL, -6891578849933910383LL, 3783206694208922581LL,
            8464961209802336085LL, 2843963751609577687LL, 3030678195484896323LL, -4429654462759003204LL,
            4459239494808162889LL, 402587895800087237LL, 8057891408711167515LL, 4541888170938985079LL,
            1042662272908816815LL, -3666068979732206850LL, 2647678726283249984LL, 2144477441549833761LL,
            -3417019821499388721LL, -2105601033380872185LL, 5916597177708541638LL, -8760774321402454447LL,
            8833658097025758785LL, 5970273481425315300LL, 563813119381731307LL, -6455022486202078793LL,
            1598828206250873866LL, -4016978389451217698LL, -2988328551145513985LL, -6071154634840136312LL,
            8469693267274066490LL, 125672920241807416LL, -3912292412830714870LL, -2559617104544284221LL,
            -486523741806024092LL, -4735332261862713930LL, 5923302823487327109LL, -9082480245771672572LL,
            -1808429243461201518LL, 7990420780896957397LL, 4317817392807076702LL, 3625184369705367340LL,
            -6482649271566653105LL, -3480272027152017464LL, -3225473396345736649LL, -368878695502291645LL,
            -3981164001421868007LL, -8522033136963788610LL, 7609280429197514109LL, 3020985755112334161LL,
            -2572049329799262942LL, 2635195723621160615LL, 5144520864246028816LL, -8188285521126945980LL,
            1567242097116389047LL, 8172389260191636581LL, -2885551685425483535LL, -7060359469858316883LL,
            -6480181133964513127LL, -7317004403633452381LL, 6011544915663598137LL, 5932255307352610768LL,
            2241128460406315459LL, -8327867140638080220LL, 3094483003111372717LL, 4583857460292963101LL,
            9079887171656594975LL, -384082854924064405LL, -3460631649611717935LL, 4225072055348026230LL,
            -7385151438465742745LL, 3801620336801580414LL, -399845416774701952LL, -7446754431269675473LL,
            7899055018877642622LL, 5421679761463003041LL, 5521102963086275121LL, -4975092593295409910LL,
            8735487530905098534LL, -7462844945281082830LL, -2080886987197029914LL, -1000715163927557685LL,
            -4253840471931071485LL, -5828896094657903328LL, 6424174453260338141LL, 359248545074932887LL,
            -5949720754023045210LL, -2426265837057637212LL, 3030918217665093212LL, -9077771202237461772LL,
            -3186796180789149575LL, 740416251634527158LL, -2142944401404840226LL, 6951781370868335478LL,
            399922722363687927LL, -8928469722407522623LL, -1378421100515597285LL, -8343051178220066766LL,
            -3030716356046100229LL, -8811767350470065420LL, 9026808440365124461LL, 6440783557497587732LL,
            4615674634722404292LL, 539897290441580544LL, 2096238225866883852LL, 8751955639408182687LL,
            -7316147128802486205LL, 7381039757301768559LL, 6157238513393239656LL, -1473377804940618233LL,
            8629571604380892756LL, 5280433031239081479LL, 7101611890139813254LL, 2479018537985767835LL,
            7169176924412769570LL, -1281305539061572506LL, -7865612307799218120LL, 2278447439451174845LL,
            3625338785743880657LL, 6477479539006708521LL, 8976185375579272206LL, -3712000482142939688LL,
            1326024180520890843LL, 7537449876596048829LL, 5464680203499696154LL, 3189671183162196045LL,
            6346751753565857109LL, -8982212049534145501LL, -6127578587196093755LL, -245039190118465649LL,
            -6320577374581628592LL, 7208698530190629697LL, 7276901792339343736LL, -7490986807540332668LL,
            4133292154170828382LL, 2918308698224194548LL, -7703910638917631350LL, -3929437324238184044LL,
            -4300543082831323144LL, -6344160503358350167LL, 5896236396443472108LL, -758328221503023383LL,
            -1894351639983151068LL, -307900319840287220LL, -6278469401177312761LL, -2171292963361310674LL,
            8382142935188824023LL, 9103922860780351547LL, 4152330101494654406LL
        };
        tap_ = 0;
        feed_ = kRngLen - kRngTap;
        seed = seed % kInt32Max;
        if (seed < 0) seed += kInt32Max;
        if (seed == 0) seed = 89482311;
        int32_t x = int32_t(seed);
        for (int i = -20; i < kRngLen; ++i) {
            x = seedrand(x);
            if (i >= 0) {
                uint64_t u = uint64_t(uint32_t(x)) << 40;
                x = seedrand(x);
                u ^= uint64_t(uint32_t(x)) << 20;
                x = seedrand(x);
                u ^= uint64_t(uint32_t(x));
                u ^= uint64_t(kRngCooked[i]);
                vec_[i] = int64_t(u);
            }
        }
    }

    int tap_ = 0;
    int feed_ = 0;
    int64_t vec_[kRngLen]{};
};


const std::vector<SudokuGrid> &allSudokuGrids() {
    static const std::vector<SudokuGrid> grids = []() {
        std::vector<SudokuGrid> res;
        res.reserve(288);
        SudokuGrid g{};
        auto dfs = [&](auto &self, int idx) -> void {
            if (idx == 16) {
                res.push_back(g);
                return;
            }
            int r = idx / 4, c = idx % 4;
            int br = (r / 2) * 2, bc = (c / 2) * 2;
            for (uint8_t num = 1; num <= 4; ++num) {
                bool ok = true;
                for (int i = 0; i < 4; ++i) {
                    if (g[r * 4 + i] == num || g[i * 4 + c] == num) { ok = false; break; }
                }
                if (ok) {
                    for (int i = 0; i < 2; ++i) {
                        for (int j = 0; j < 2; ++j) {
                            if (g[(br + i) * 4 + (bc + j)] == num) { ok = false; break; }
                        }
                    }
                }
                if (ok) {
                    g[idx] = num;
                    self(self, idx + 1);
                    g[idx] = 0;
                }
            }
        };
        dfs(dfs, 0);
        return res;
    }();
    return grids;
}



SudokuLayout buildSudokuLayout(bool preferAscii, const std::string &customPattern) {
    SudokuLayout layout;
    if (preferAscii) {
        layout.isAscii = true;
        layout.isCustom = false;
        layout.populateLookupTables();
        for (int i = 0; i < 32; ++i) layout.paddingPool.push_back(uint8_t(0x20 + i));
        return layout;
    }
    if (!customPattern.empty() && isValidCustomTablePattern(customPattern)) {
        layout.isAscii = false;
        layout.isCustom = true;
        int xi = 0, pi = 0, vi = 0;
        for (int i = 0; i < 8; ++i) {
            uint8_t bit = uint8_t(7 - i);
            char c = customPattern[size_t(i)];
            if (c == 'x') layout.xBits[xi++] = bit;
            else if (c == 'p') layout.pBits[pi++] = bit;
            else if (c == 'v') layout.vBits[vi++] = bit;
        }
        layout.xMask = uint8_t((1u << layout.xBits[0]) | (1u << layout.xBits[1]));
        layout.populateLookupTables();
        bool seen[256]{};
        for (int drop = 0; drop < 2; ++drop) {
            for (uint8_t val = 0; val < 4; ++val) {
                for (uint8_t pos = 0; pos < 16; ++pos) {
                    if (__builtin_popcount(pos) >= 2) {
                        uint8_t b = layout.encodeGroup(uint8_t((val << 4) | pos));
                        b &= uint8_t(~(1u << layout.xBits[drop]));
                        if (!seen[b]) {
                            seen[b] = true;
                            layout.paddingPool.push_back(b);
                        }
                    }
                }
            }
        }
        return layout;
    }
    layout.isAscii = false;
    layout.isCustom = false;
    layout.populateLookupTables();
    for (int i = 0; i < 8; ++i) {
        layout.paddingPool.push_back(uint8_t(0x80 + i));
        layout.paddingPool.push_back(uint8_t(0x10 + i));
    }
    return layout;
}


std::shared_ptr<const SudokuTable> getSudokuTable(const std::string &masterKey, bool preferAscii, const std::string &customPattern) {
    static std::mutex cacheMutex;
    static std::unordered_map<std::string, std::shared_ptr<const SudokuTable>> cache;
    std::string cacheKey = masterKey + "|" + (preferAscii ? "A" : ("E:" + customPattern));
    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        auto it = cache.find(cacheKey);
        if (it != cache.end()) return it->second;
    }

    auto table = std::make_shared<SudokuTable>();
    table->layout = buildSudokuLayout(preferAscii, customPattern);

    Buffer keyBytes(masterKey.begin(), masterKey.end());
    Buffer digest = crypto::digest("SHA256", keyBytes);
    int64_t seed = int64_t(readBE64(digest.data()));
    GoRng rng(seed);

    std::vector<SudokuGrid> shuffled = allSudokuGrids();
    for (int i = int(shuffled.size()) - 1; i > 0; --i) {
        int j = rng.int31n(int32_t(i + 1));
        std::swap(shuffled[size_t(i)], shuffled[size_t(j)]);
    }

    // Populate hintSets across all 288 shuffled grids (0..287) matching SUDOKU-ASCII/sudoku table.go
    for (uint16_t b = 0; b < uint16_t(shuffled.size()); ++b) {
        const auto &g = shuffled[size_t(b)];
        for (uint8_t pos = 0; pos < 16; ++pos) {
            uint8_t val = g[pos] - 1;
            table->hintSets[(val << 4) | pos].set(b);
        }
    }

    for (int b = 0; b < 256; ++b) {
        const auto &g = shuffled[size_t(b)];
        for (uint8_t p0 = 0; p0 < 13; ++p0) {
            const auto &s0 = table->hintSets[((g[p0] - 1) << 4) | p0];
            for (uint8_t p1 = p0 + 1; p1 < 14; ++p1) {
                const auto &s1 = table->hintSets[((g[p1] - 1) << 4) | p1];
                uint64_t m01[5] = {
                    s0.w[0] & s1.w[0], s0.w[1] & s1.w[1],
                    s0.w[2] & s1.w[2], s0.w[3] & s1.w[3],
                    s0.w[4] & s1.w[4]
                };
                for (uint8_t p2 = p1 + 1; p2 < 15; ++p2) {
                    const auto &s2 = table->hintSets[((g[p2] - 1) << 4) | p2];
                    uint64_t m012[5] = {
                        m01[0] & s2.w[0], m01[1] & s2.w[1],
                        m01[2] & s2.w[2], m01[3] & s2.w[3],
                        m01[4] & s2.w[4]
                    };
                    for (uint8_t p3 = p2 + 1; p3 < 16; ++p3) {
                        const auto &s3 = table->hintSets[((g[p3] - 1) << 4) | p3];
                        if ((m012[4] & s3.w[4]) != 0) continue;
                        uint64_t r0 = m012[0] & s3.w[0];
                        uint64_t r1 = m012[1] & s3.w[1];
                        uint64_t r2 = m012[2] & s3.w[2];
                        uint64_t r3 = m012[3] & s3.w[3];
                        int pop = __builtin_popcountll(r0) +
                                  __builtin_popcountll(r1) +
                                  __builtin_popcountll(r2) +
                                  __builtin_popcountll(r3);
                        if (pop == 1) {
                            table->encodeTable[size_t(b)].push_back({
                                table->layout.encodeHint(g[p0] - 1, p0),
                                table->layout.encodeHint(g[p1] - 1, p1),
                                table->layout.encodeHint(g[p2] - 1, p2),
                                table->layout.encodeHint(g[p3] - 1, p3)
                            });
                        }
                    }
                }
            }
        }
    }

    std::lock_guard<std::mutex> lock(cacheMutex);
    cache[cacheKey] = table;
    return table;
}



void sudokuAppendEncodedBytes(Buffer &out, const Buffer &input, const SudokuTable &table, uint32_t paddingMin, uint32_t paddingMax) {
    out.reserve(out.size() + input.size() * 5 + 8);
    const auto &padPool = table.layout.paddingPool;
    const size_t padSize = padPool.size();
    const bool usePadding = (paddingMax > 0 && padSize > 0);
    const uint32_t padSpan = (paddingMax > paddingMin) ? (paddingMax - paddingMin + 1) : 0;

    if (!usePadding) {
        for (uint8_t b : input) {
            const auto &puzzles = table.encodeTable[b];
            if (puzzles.empty()) throw std::runtime_error("Sudoku encode table missing puzzle for byte");
            uint64_t r = fastWyRand();
            const auto &clues = puzzles[size_t(uint32_t(r)) % puzzles.size()];
            uint8_t p0 = clues[0], p1 = clues[1], p2 = clues[2], p3 = clues[3];
            uint32_t pr = uint32_t(r >> 32);
            uint8_t perm[4] = {p0, p1, p2, p3};
            std::swap(perm[3], perm[pr & 3u]);
            std::swap(perm[2], perm[(pr >> 2) % 3u]);
            std::swap(perm[1], perm[(pr >> 4) & 1u]);
            out.push_back(perm[0]);
            out.push_back(perm[1]);
            out.push_back(perm[2]);
            out.push_back(perm[3]);
        }
        return;
    }

    auto maybePad = [&](uint32_t rand16) {
        uint32_t rate = paddingMin + (padSpan ? (uint32_t(rand16 & 0xffu) % padSpan) : 0u);
        if ((uint32_t((rand16 >> 8) & 0xffu) % 100u) < rate) {
            out.push_back(padPool[size_t(rand16) % padSize]);
        }
    };

    for (uint8_t b : input) {
        const auto &puzzles = table.encodeTable[b];
        if (puzzles.empty()) throw std::runtime_error("Sudoku encode table missing puzzle for byte");
        uint64_t r1 = fastWyRand();
        uint64_t r2 = fastWyRand();
        const auto &clues = puzzles[size_t(uint32_t(r1)) % puzzles.size()];
        uint32_t pr = uint32_t(r1 >> 32);
        uint8_t perm[4] = {clues[0], clues[1], clues[2], clues[3]};
        std::swap(perm[3], perm[pr & 3u]);
        std::swap(perm[2], perm[(pr >> 2) % 3u]);
        std::swap(perm[1], perm[(pr >> 4) & 1u]);
        for (int i = 0; i < 4; ++i) {
            maybePad(uint32_t((r2 >> (i * 16)) & 0xffffu));
            out.push_back(perm[i]);
        }
    }
    maybePad(uint32_t(fastWyRand() & 0xffffu));
}

Buffer sudokuEncodeBytes(const Buffer &input, const SudokuTable &table, uint32_t paddingMin, uint32_t paddingMax) {
    Buffer out;
    sudokuAppendEncodedBytes(out, input, table, paddingMin, paddingMax);
    return out;
}

// Helper for self-tests and synchronous buffers
Buffer sudokuEncodeTable(const Buffer &input, bool preferAscii, const std::string &customTable) {
    auto tbl = getSudokuTable("sudoku-selftest-key", preferAscii, customTable);
    return sudokuEncodeBytes(input, *tbl, 0, 0);
}

Buffer sudokuDecodeTable(const Buffer &input, bool preferAscii, const std::string &customTable) {
    auto tbl = getSudokuTable("sudoku-selftest-key", preferAscii, customTable);
    Buffer out;
    uint8_t hints[4];
    int count = 0;
    for (uint8_t wire : input) {
        if (!tbl->layout.isHint(wire)) continue;
        hints[count++] = wire;
        if (count == 4) {
            uint8_t decoded = 0;
            if (!tbl->solve4Hints(hints, decoded)) {
                throw std::runtime_error("Invalid Sudoku 4-hint puzzle");
            }
            out.push_back(decoded);
            count = 0;
        }
    }
    if (count != 0) throw std::runtime_error("Incomplete Sudoku hint group");
    return out;
}

// HKDF-Expand-SHA256 using an existing 32-byte PRK directly (matches hkdf.Expand(sha256.New, sum[:], info))
Buffer hkdfExpandSHA256(const Buffer &prk, const std::string &infoStr, size_t outLen) {
    Buffer info(infoStr.begin(), infoStr.end());
    Buffer out;
    out.reserve(outLen);
    Buffer prev;
    for (uint8_t counter = 1; out.size() < outLen; ++counter) {
        Buffer msg = prev;
        msg.insert(msg.end(), info.begin(), info.end());
        msg.push_back(counter);
        prev = crypto::hmac("SHA256", prk, msg);
        size_t take = std::min(prev.size(), outLen - out.size());
        out.insert(out.end(), prev.begin(), prev.begin() + take);
    }
    return out;
}

void deriveSudokuPSKDirectionalBases(const std::string &masterPubKey, Buffer &outC2S, Buffer &outS2C) {
    static std::mutex pskCacheMutex;
    static std::unordered_map<std::string, std::pair<Buffer, Buffer>> pskCache;
    {
        std::lock_guard<std::mutex> lock(pskCacheMutex);
        auto it = pskCache.find(masterPubKey);
        if (it != pskCache.end()) {
            outC2S = it->second.first;
            outS2C = it->second.second;
            return;
        }
        if (pskCache.size() > 64) pskCache.clear();
    }
    Buffer keyBytes(masterPubKey.begin(), masterPubKey.end());
    Buffer sum = crypto::digest("SHA256", keyBytes);
    outC2S = hkdfExpandSHA256(sum, "sudoku-psk-c2s", 32);
    outS2C = hkdfExpandSHA256(sum, "sudoku-psk-s2c", 32);
    std::lock_guard<std::mutex> lock(pskCacheMutex);
    pskCache.emplace(masterPubKey, std::make_pair(outC2S, outS2C));
}

void deriveSudokuSessionDirectionalBases(const std::string &masterPubKey, const Buffer &shared32,
                                         const Buffer &nonce16, Buffer &outC2S, Buffer &outS2C) {
    Buffer keyBytes(masterPubKey.begin(), masterPubKey.end());
    Buffer salt = crypto::digest("SHA256", keyBytes);
    Buffer ikm;
    ikm.reserve(shared32.size() + nonce16.size());
    ikm.insert(ikm.end(), shared32.begin(), shared32.end());
    ikm.insert(ikm.end(), nonce16.begin(), nonce16.end());
    Buffer infoC2S{'s','u','d','o','k','u','-','s','e','s','s','i','o','n','-','c','2','s'};
    Buffer infoS2C{'s','u','d','o','k','u','-','s','e','s','s','i','o','n','-','s','2','c'};
    outC2S = crypto::hkdf("SHA256", ikm, salt, infoC2S, 32);
    outS2C = crypto::hkdf("SHA256", ikm, salt, infoS2C, 32);
}

Buffer deriveSudokuEpochKey(const Buffer &baseKey32, const std::string &aeadMethod, uint32_t epoch) {
    std::string prefix = "sudoku-record:" + aeadMethod;
    Buffer msg(prefix.begin(), prefix.end());
    appendBE32(msg, epoch);
    Buffer mac = crypto::hmac("SHA256", baseKey32, msg);
    size_t keyLen = (aeadMethod == "aes-128-gcm") ? 16 : 32;
    mac.resize(keyLen);
    return mac;
}

uint32_t randomNonZeroUint32() {
    Buffer r = crypto::randomBytes(4);
    uint32_t v = readBE32(r.data());
    return v == 0 ? 1u : v;
}

uint64_t randomNonZeroUint64() {
    Buffer r = crypto::randomBytes(8);
    uint64_t v = readBE64(r.data());
    return v == 0 ? 1ULL : v;
}

void generateX25519KeyPair(Buffer &outPriv32, Buffer &outPub32) {
    using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
    using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    PkeyCtxPtr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr), EVP_PKEY_CTX_free);
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) {
        throw std::runtime_error("X25519 keygen init failed");
    }
    EVP_PKEY *rawPkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &rawPkey) <= 0 || !rawPkey) {
        throw std::runtime_error("X25519 keygen failed");
    }
    PkeyPtr pkey(rawPkey, EVP_PKEY_free);
    size_t privLen = 32, pubLen = 32;
    outPriv32.resize(32);
    outPub32.resize(32);
    if (EVP_PKEY_get_raw_private_key(pkey.get(), outPriv32.data(), &privLen) <= 0 ||
        EVP_PKEY_get_raw_public_key(pkey.get(), outPub32.data(), &pubLen) <= 0) {
        throw std::runtime_error("X25519 key extraction failed");
    }
}

Buffer computeX25519Shared(const Buffer &priv32, const Buffer &peerPub32) {
    using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
    PkeyPtr myKey(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv32.data(), priv32.size()), EVP_PKEY_free);
    PkeyPtr peerKey(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peerPub32.data(), peerPub32.size()), EVP_PKEY_free);
    if (!myKey || !peerKey) throw std::runtime_error("Invalid X25519 key material");
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new(myKey.get(), nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx.get(), peerKey.get()) <= 0) {
        throw std::runtime_error("X25519 derive init failed");
    }
    size_t secretLen = 32;
    Buffer shared(32, 0);
    if (EVP_PKEY_derive(ctx.get(), shared.data(), &secretLen) <= 0 || secretLen != 32) {
        throw std::runtime_error("X25519 shared secret derivation failed");
    }
    bool allZero = true;
    for (uint8_t b : shared) { if (b != 0) { allZero = false; break; } }
    if (allZero) throw std::runtime_error("X25519 rejected low-order public key");
    return shared;
}


Buffer buildKIPMessage(uint8_t type, const Buffer &payload) {
    Buffer out{'k', 'i', 'p', type};
    appendBE16(out, uint16_t(payload.size()));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}




} // namespace hajimi::sudoku_detail
