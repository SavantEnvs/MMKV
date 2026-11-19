// Fuzz MMKV's typed value decoders: the input is stored verbatim as a raw value (set(MMBuffer)) and
// then read back through every typed getter, so the attacker controls the value bytes that
// MiniPBCoder::decodeVector / CodedInputData readString/readBytes/varint paths parse.
#include "fuzz_common.h"
#include <span>

static const char *kID = "val";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void) fz::root();
    MMKV *kv = MMKV::mmkvWithID(kID);
    if (!kv) {
        abort();
    }
    mmkv::MMBuffer value((void *) data, size, mmkv::MMBufferNoCopy);
    kv->set(value, "k");

    std::vector<std::string> vs;
    (void) kv->getVector("k", vs);
    std::vector<int32_t> v32;
    (void) kv->getVector("k", v32);
    std::vector<uint32_t> vu32;
    (void) kv->getVector("k", vu32);
    std::vector<int64_t> v64;
    (void) kv->getVector("k", v64);
    std::vector<uint64_t> vu64;
    (void) kv->getVector("k", vu64);
    std::vector<double> vd;
    (void) kv->getVector("k", vd);
    std::vector<float> vf;
    (void) kv->getVector("k", vf);
    std::vector<bool> vb;
    (void) kv->getVector("k", vb);
    std::string str;
    (void) kv->getString("k", str, true);
    (void) kv->getString("k", str, false);
    (void) kv->getBytes("k");
    (void) kv->getInt32("k");
    (void) kv->getUInt32("k");
    (void) kv->getInt64("k");
    (void) kv->getUInt64("k");
    (void) kv->getDouble("k");
    (void) kv->getFloat("k");
    (void) kv->getBool("k");
    (void) kv->getValueSize("k", true);
    (void) kv->getValueSize("k", false);
    char small[8];
    (void) kv->writeValueToBuffer("k", small, sizeof(small));

    kv->close();
    MMKV::removeStorage(kID);
    return 0;
}
