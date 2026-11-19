// Seed generator (not part of the build): writes real MMKV stores through the public API and packs
// each <id>.crc + <id> pair into the harness input layout (mayhem/harnesses/fuzz_common.h):
//   [flags][meta len][meta bytes][data bytes]
// Usage (inside the commit image):
//   clang++ -std=c++20 -DMMKV_EMBED_ZLIB=1 -ICore mayhem/tools/gen_seeds.cpp build/test/libcore.a -lpthread -o /tmp/gen
//   /tmp/gen <outdir>     -> <outdir>/{load,crypt,expire,value,ops}/seed_*
#include "MMKV.h"
#include "MMKVMetaInfo.hpp"
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

static std::string root;

static std::vector<char> slurp(const std::string &p) {
    std::ifstream f(p, std::ios::binary);
    return std::vector<char>(std::istreambuf_iterator<char>(f), {});
}

static void put(const std::string &path, const std::vector<char> &v) {
    std::ofstream f(path, std::ios::binary);
    f.write(v.data(), v.size());
}

static void fill(MMKV *kv, int variant) {
    kv->set(true, "bool");
    kv->set((int32_t) -7, "i32");
    kv->set((int64_t) 1234567890123LL, "i64");
    kv->set(3.25, "dbl");
    kv->set("hello world", "str");
    kv->set(std::vector<std::string>{"a", "bc", "def"}, "vec");
    if (variant > 0) {
        kv->set(std::vector<int32_t>{1, -2, 3}, "vi32");
        kv->set(std::string(300, 'x'), "long");
        kv->removeValueForKey("bool");
    }
}

static void pack(const std::string &id, uint8_t flags, const std::string &out) {
    auto meta = slurp(root + "/" + id + ".crc");
    auto data = slurp(root + "/" + id);
    size_t ml = std::min<size_t>(sizeof(mmkv::MMKVMetaInfo), meta.size());
    uint32_t actual = 0;
    if (data.size() >= 4) memcpy(&actual, data.data(), 4);
    if (meta.size() >= sizeof(mmkv::MMKVMetaInfo)) {
        auto *mi = (const mmkv::MMKVMetaInfo *) meta.data();
        actual = std::max(actual, mi->m_actualSize);
    }
    size_t dl = std::min<size_t>(data.size(), 4 + (size_t) actual);
    std::vector<char> v;
    v.push_back((char) flags);
    v.push_back((char) ml);
    v.insert(v.end(), meta.begin(), meta.begin() + ml);
    v.insert(v.end(), data.begin(), data.begin() + dl);
    put(out, v);
}

int main(int argc, char **argv) {
    std::string out = argv[1];
    char tmpl[] = "/tmp/mmkv-seed.XXXXXX";
    root = mkdtemp(tmpl);
    MMKV::initializeMMKV(root, MMKVLogNone);
    for (auto d : {"load", "crypt", "expire", "value", "ops"}) mkdir((out + "/" + d).c_str(), 0755);

    static const std::string k128 = "0123456789abcdef", k256 = "0123456789abcdef0123456789abcdef";
    for (int variant = 0; variant < 2; variant++) {
        std::string sfx = std::to_string(variant);
        {   // plain
            MMKV *kv = MMKV::mmkvWithID("p" + sfx);
            fill(kv, variant);
            if (variant) kv->trim();
            kv->close();
            pack("p" + sfx, variant ? 1 : 0, out + "/load/seed_plain" + sfx);
        }
        {   // encrypted (aes128 for variant 0, aes256 for variant 1)
            MMKVConfig c;
            c.cryptKey = variant ? &k256 : &k128;
            c.aes256 = variant == 1;
            MMKV *kv = MMKV::mmkvWithID("c" + sfx, c);
            fill(kv, variant);
            kv->close();
            pack("c" + sfx, variant ? (8 | 1) : 1, out + "/crypt/seed_crypt" + sfx);
        }
        {   // expiration enabled
            MMKVConfig c;
            c.enableKeyExpire = true;
            c.expiredInSeconds = 3600;
            MMKV *kv = MMKV::mmkvWithID("e" + sfx, c);
            fill(kv, variant);
            kv->set("soon", "exp", 1u);
            kv->close();
            pack("e" + sfx, (uint8_t) (1 | (variant << 5)), out + "/expire/seed_expire" + sfx);
        }
    }
    {   // raw encoded values for the value decoder
        MMKV *kv = MMKV::mmkvWithID("v");
        fill(kv, 1);
        int n = 0;
        for (auto k : kv->allKeys()) {
            auto b = kv->getBytes(k);
            if (b.length() == 0) continue;
            std::vector<char> v((char *) b.getPtr(), (char *) b.getPtr() + b.length());
            put(out + "/value/seed_" + std::to_string(n++) + "_" + k, v);
        }
        kv->close();
    }
    {   // op sequences: deterministic pseudo-random byte strings (FuzzedDataProvider input)
        uint32_t x = 12345;
        for (int n = 0; n < 4; n++) {
            std::vector<char> v(64 + 64 * n);
            for (auto &c : v) { x = x * 1103515245u + 12345u; c = (char) (x >> 16); }
            put(out + "/ops/seed_" + std::to_string(n), v);
        }
    }
    return 0;
}
