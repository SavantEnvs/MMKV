// Fuzz MMKV's on-disk format: a fuzzed data file <id> plus meta file <id>.crc are opened through the
// public MMKV::mmkvWithID() (loadFromFile / loadMetaInfoAndCheck / checkDataValid / MiniPBCoder
// decodeMap, KeyValueHolder, CodedInputData), then every key is read back, a key is written
// (append / full write-back), the file is trimmed, the cache dropped and the file re-read.
//
// Built three times from this one source:
//   (default)        plain store
//   -DFZ_CRYPT=1     AES-CFB encrypted store (CodedInputDataCrypt, KeyValueHolderCrypt, reKey)
//   -DFZ_EXPIRE=1    key-expiration enabled (filterExpiredKeys, getDataWithoutMTimeForKey)
//
// flags byte: bit0 recover strategy (OnErrorRecover vs OnErrorDiscard), bit1 multi-process mode,
//             bit2 compare-before-set, bit3 AES-256 (crypt) / re-enable expire (expire),
//             bit4 reKey to empty (decrypt) vs to another key (crypt), bits5-7 expire seconds.
#include "fuzz_common.h"

static const char *kID = "fz";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const std::string &dir = fz::root();
    fz::Split s = fz::split(data, size);
    fz::writePair(dir, kID, s);

    MMKVConfig cfg;
    cfg.mode = (s.flags & 2) ? MMKV_MULTI_PROCESS : MMKV_SINGLE_PROCESS;
    cfg.recover = (s.flags & 1) ? OnErrorRecover : OnErrorDiscard;
    cfg.enableCompareBeforeSet = (s.flags & 4) != 0;
#if defined(FZ_CRYPT)
    static const std::string key128 = "0123456789abcdef";
    static const std::string key256 = "0123456789abcdef0123456789abcdef";
    cfg.aes256 = (s.flags & 8) != 0;
    cfg.cryptKey = cfg.aes256 ? &key256 : &key128;
    cfg.enableCompareBeforeSet = false; // not supported together with encryption
#elif defined(FZ_EXPIRE)
    cfg.enableKeyExpire = true;
    cfg.expiredInSeconds = (s.flags >> 5) * 60;
    cfg.enableCompareBeforeSet = false; // not supported together with key expiration
#endif

    MMKV *kv = MMKV::mmkvWithID(kID, cfg);
    if (!kv) {
        MMKV::removeStorage(kID);
        return 0;
    }
#if defined(FZ_EXPIRE)
    fz::readAll(kv, true);
    fz::readAll(kv, false);
    kv->set("fuzz-value", "fz-new-key", kv->isExpirationEnabled() ? 3600u : MMKV::ExpireNever);
    kv->set((int64_t) 42, "fz-int-key", MMKV::ExpireNever);
    if (s.flags & 8) {
        kv->disableAutoKeyExpire();
        kv->enableAutoKeyExpire(1);
    }
#else
    fz::readAll(kv, false);
    kv->set("fuzz-value", "fz-new-key");
    kv->set((int64_t) 42, "fz-int-key");
#endif
#if defined(FZ_CRYPT)
    if (s.flags & 16) {
        kv->reKey("");
    } else {
        kv->reKey(cfg.aes256 ? key128 : key256, !cfg.aes256);
    }
    fz::readAll(kv, false);
#endif
    kv->removeValueForKey("fz-int-key");
    kv->trim();
    kv->clearMemoryCache();
    fz::readAll(kv, false);
    kv->close();
    MMKV::removeStorage(kID);
    return 0;
}
