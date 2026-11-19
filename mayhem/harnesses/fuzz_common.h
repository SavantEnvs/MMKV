// Shared helpers for the MMKV fuzz harnesses.
//
// Process-global state kept across inputs (on purpose, and why it is safe):
//  * one private scratch root created with mkdtemp() under $TMPDIR and MMKV::initializeMMKV() on it
//    (MMKV allows a single global root; it is never changed afterwards);
//  * the log level is set once to MMKVLogNone and never changed by any input.
// Every harness rewrites the files it opens and close()s / removeStorage()s every instance it opened
// before returning, so the next input re-parses from scratch.
#pragma once
#include "MMKV.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace fz {

inline const std::string &root() {
    static std::string r = [] {
        const char *t = getenv("TMPDIR");
        std::string tmpl = std::string((t && *t) ? t : "/tmp") + "/mmkv-fuzz.XXXXXX";
        if (!mkdtemp(tmpl.data())) {
            abort();
        }
        MMKV::initializeMMKV(tmpl, MMKVLogNone);
        return tmpl;
    }();
    return r;
}

inline std::string subdir(const char *name) {
    std::string d = root() + "/" + name;
    mkdir(d.c_str(), 0700);
    return d;
}

inline void writeFile(const std::string &path, const uint8_t *data, size_t len) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        abort();
    }
    while (len > 0) {
        ssize_t n = write(fd, data, len);
        if (n <= 0) {
            abort();
        }
        data += n;
        len -= (size_t) n;
    }
    close(fd);
}

// Input layout for the on-disk targets:
//   byte 0      option flags (harness specific)
//   byte 1      length L of the meta file (<id>.crc, struct MMKVMetaInfo)
//   L bytes     meta file content
//   rest        data file content (<id>: 4-byte actual size + KV stream)
struct Split {
    uint8_t flags = 0;
    const uint8_t *meta = nullptr;
    size_t metaLen = 0;
    const uint8_t *body = nullptr;
    size_t bodyLen = 0;
};

inline Split split(const uint8_t *data, size_t size) {
    Split s;
    size_t pos = 0;
    if (pos < size) s.flags = data[pos++];
    size_t want = (pos < size) ? data[pos++] : 0;
    s.meta = data + pos;
    s.metaLen = (want <= size - pos) ? want : size - pos;
    pos += s.metaLen;
    s.body = data + pos;
    s.bodyLen = size - pos;
    return s;
}

inline void writePair(const std::string &dir, const std::string &id, const Split &s) {
    writeFile(dir + "/" + id + ".crc", s.meta, s.metaLen);
    writeFile(dir + "/" + id, s.body, s.bodyLen);
}

// Read every key back through the public getters (decode paths for each value type).
inline void readAll(MMKV *kv, bool filterExpire) {
    auto keys = kv->allKeys(filterExpire);
    (void) kv->count(filterExpire);
    (void) kv->totalSize();
    (void) kv->actualSize();
    size_t n = 0;
    for (const auto &k : keys) {
        if (++n > 128) break;
        std::string str;
        (void) kv->getString(k, str, true);
        (void) kv->getString(k, str, false);
        mmkv::MMBuffer buf;
        (void) kv->getBytes(k, buf);
        (void) kv->getInt32(k);
        (void) kv->getUInt32(k);
        (void) kv->getInt64(k);
        (void) kv->getUInt64(k);
        (void) kv->getBool(k);
        (void) kv->getFloat(k);
        (void) kv->getDouble(k);
        std::vector<std::string> vs;
        (void) kv->getVector(k, vs);
        std::vector<int64_t> vi;
        (void) kv->getVector(k, vi);
        (void) kv->getValueSize(k, true);
        (void) kv->getValueSize(k, false);
        char small[16];
        (void) kv->writeValueToBuffer(k, small, sizeof(small));
        (void) kv->containsKey(k);
    }
}

} // namespace fz
