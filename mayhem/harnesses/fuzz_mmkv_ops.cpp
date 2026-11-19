// Fuzz MMKV's public mutation API with an operation sequence on a fresh store: setters/getters,
// removal, trim, clearMemoryCache (forces a reload from disk), reKey, expiration toggles, clearAll.
// Reaches MMKV_IO appendDataWithKey / ensureMemorySize / fullWriteback / expandAndWriteBack,
// CodedOutputData, MiniPBCoder encode and KeyValueHolder size limits (oversized keys and values).
#include "fuzz_common.h"
#include <fuzzer/FuzzedDataProvider.h>

static const char *kID = "ops";

static std::string makeKey(FuzzedDataProvider &fdp) {
    if (fdp.ConsumeIntegralInRange<int>(0, 15) == 0) {
        // oversized key (> 64 KiB) to reach KeyValueHolder length limits
        size_t n = fdp.ConsumeIntegralInRange<size_t>(60000, 70000);
        return std::string(n, (char) fdp.ConsumeIntegral<uint8_t>());
    }
    return fdp.ConsumeRandomLengthString(32);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void) fz::root();
    FuzzedDataProvider fdp(data, size);
    MMKV::removeStorage(kID);

    static const std::string key128 = "0123456789abcdef";
    static const std::string key256 = "0123456789abcdef0123456789abcdef";
    uint8_t flags = fdp.ConsumeIntegral<uint8_t>();
    MMKVConfig cfg;
    if (flags & 1) {
        cfg.aes256 = (flags & 2) != 0;
        cfg.cryptKey = cfg.aes256 ? &key256 : &key128;
    }
    if (flags & 4) {
        cfg.enableKeyExpire = true;
        cfg.expiredInSeconds = (flags >> 5);
    } else if (!(flags & 1) && (flags & 8)) {
        cfg.enableCompareBeforeSet = true;
    }
    if (flags & 16) {
        cfg.itemSizeLimit = 1024;
    }
    MMKV *kv = MMKV::mmkvWithID(kID, cfg);
    if (!kv) {
        abort();
    }

    for (int i = 0; i < 64 && fdp.remaining_bytes() > 0; i++) {
        uint8_t op = fdp.ConsumeIntegralInRange<uint8_t>(0, 24);
        std::string key = makeKey(fdp);
        switch (op) {
        case 0: kv->set(fdp.ConsumeRandomLengthString(256), key); break;
        case 1: {
            auto b = fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, 4096));
            kv->set(b.empty() ? mmkv::MMBuffer() : mmkv::MMBuffer(b.data(), b.size()), key);
            break;
        }
        case 2: kv->set(fdp.ConsumeIntegral<int32_t>(), key); break;
        case 3: kv->set(fdp.ConsumeIntegral<int64_t>(), key); break;
        case 4: kv->set(fdp.ConsumeIntegral<uint64_t>(), key); break;
        case 5: kv->set(fdp.ConsumeFloatingPoint<double>(), key); break;
        case 6: kv->set(fdp.ConsumeBool(), key); break;
        case 7: {
            std::vector<std::string> v;
            int n = fdp.ConsumeIntegralInRange<int>(0, 8);
            for (int j = 0; j < n; j++) v.push_back(fdp.ConsumeRandomLengthString(64));
            kv->set(v, key);
            break;
        }
        case 8: {
            // A per-key expire duration is only valid once auto key expiry is enabled
            // (MMKV asserts this precondition, Core/MMKV.cpp setDataForKey).
            uint32_t dur = fdp.ConsumeIntegral<uint32_t>();
            kv->set(fdp.ConsumeRandomLengthString(64), key, kv->isExpirationEnabled() ? dur : MMKV::ExpireNever);
            break;
        }
        case 9: {
            std::string s;
            kv->getString(key, s);
            break;
        }
        case 10: (void) kv->getBytes(key); (void) kv->getInt64(key); (void) kv->getDouble(key); break;
        case 11: {
            std::vector<std::string> v;
            kv->getVector(key, v);
            break;
        }
        case 12: kv->removeValueForKey(key); break;
        case 13: kv->removeValuesForKeys({key, fdp.ConsumeRandomLengthString(16)}); break;
        case 14: (void) kv->containsKey(key); (void) kv->getValueSize(key, true); break;
        case 15: kv->trim(); break;
        case 16: kv->clearMemoryCache(); break;
        case 17: {
            uint8_t r = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
            if (r == 0) kv->reKey("");
            else kv->reKey(r == 1 ? key128 : key256, r == 2);
            break;
        }
        case 18: (void) kv->count(true); (void) kv->allKeys(true); break;
        case 19: kv->sync(MMKV_SYNC); break;
        case 20: kv->clearAll(fdp.ConsumeBool()); break;
        case 21: kv->enableAutoKeyExpire(fdp.ConsumeIntegralInRange<uint32_t>(0, 3600)); break;
        case 22: kv->disableAutoKeyExpire(); break;
        case 23: {
            std::vector<int32_t> v = {fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>()};
            kv->set(v, key);
            std::vector<int32_t> out;
            kv->getVector(key, out);
            break;
        }
        case 24: {
            char buf[32];
            kv->writeValueToBuffer(key, buf, sizeof(buf));
            break;
        }
        }
    }
    fz::readAll(kv, false);
    kv->close();
    MMKV::removeStorage(kID);
    return 0;
}
