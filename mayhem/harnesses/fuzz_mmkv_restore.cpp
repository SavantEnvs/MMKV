// Fuzz MMKV's file validation, restore, import and backup paths on a fuzzed store:
// MMKV::isFileValid(), restoreOneFromDirectory() (copy into the root), open the restored store,
// MMKV::importFrom() into a fresh store, backupOneToDirectory(). Input layout: fuzz_common.h.
// flags byte: bit0 recover strategy, bit1 open destination encrypted.
#include "fuzz_common.h"

static const char *kID = "rs";
static const char *kDst = "rs-dst";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void) fz::root();
    static const std::string srcDir = fz::subdir("restore-src");
    static const std::string bakDir = fz::subdir("restore-bak");
    fz::Split s = fz::split(data, size);
    fz::writePair(srcDir, kID, s);

    (void) MMKV::isFileValid(kID, &srcDir);
    (void) MMKV::restoreOneFromDirectory(kID, srcDir);

    MMKVConfig cfg;
    cfg.recover = (s.flags & 1) ? OnErrorRecover : OnErrorDiscard;
    MMKV *src = MMKV::mmkvWithID(kID, cfg);
    if (src) {
        fz::readAll(src, false);
        MMKVConfig dcfg;
        static const std::string key = "fedcba9876543210";
        if (s.flags & 2) {
            dcfg.cryptKey = &key;
        }
        MMKV *dst = MMKV::mmkvWithID(kDst, dcfg);
        if (dst) {
            (void) dst->importFrom(src);
            fz::readAll(dst, false);
            dst->close();
        }
        (void) MMKV::backupOneToDirectory(kID, bakDir);
        src->close();
    }
    MMKV::removeStorage(kID);
    MMKV::removeStorage(kDst);
    MMKV::removeStorage(kID, &srcDir);
    MMKV::removeStorage(kID, &bakDir);
    return 0;
}
