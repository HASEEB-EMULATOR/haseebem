#include "haseeb/cpio_reader.hpp"

#include <cstdio>
#include <cstring>

namespace haseeb::vm {

namespace {

bool ParseHex8(const uint8_t* p, uint32_t& out) {
    uint32_t v = 0;
    for (int i = 0; i < 8; ++i) {
        uint8_t c = p[i];
        uint32_t nib = 0;
        if (c >= '0' && c <= '9') nib = c - '0';
        else if (c >= 'a' && c <= 'f') nib = c - 'a' + 10u;
        else if (c >= 'A' && c <= 'F') nib = c - 'A' + 10u;
        else return false;
        v = (v << 4) | nib;
    }
    out = v;
    return true;
}

size_t Align4(size_t n) {
    return (n + 3u) & ~size_t(3u);
}

std::string NormalizeCpioPath(const std::string& path) {
    size_t start = 0;
    while (start < path.size()) {
        if (path[start] == '/') {
            ++start;
        } else if (path.compare(start, 2, "./") == 0) {
            start += 2u;
        } else {
            break;
        }
    }
    return path.substr(start);
}

} // namespace

bool CpioArchive::LooksLikeNewc(const std::vector<uint8_t>& bytes) {
    return bytes.size() >= 6u &&
           (std::memcmp(bytes.data(), "070701", 6) == 0 ||
            std::memcmp(bytes.data(), "070702", 6) == 0);
}

bool CpioArchive::Parse(const std::vector<uint8_t>& bytes,
                        std::vector<CpioEntry>& out_entries,
                        std::string& out_error) {
    out_entries.clear();
    size_t pos = 0;

    while (pos < bytes.size()) {
        // Skip NUL padding between concatenated CPIO archives
        while (pos < bytes.size() && bytes[pos] == 0u) {
            ++pos;
        }
        if (pos >= bytes.size()) break;
        if (bytes.size() - pos < 110u) {
            out_error = "Truncated CPIO newc header";
            return false;
        }

        const uint8_t* hdr = bytes.data() + pos;
        if (std::memcmp(hdr, "070701", 6) != 0 && std::memcmp(hdr, "070702", 6) != 0) {
            out_error = "Invalid CPIO newc magic";
            return false;
        }

        uint32_t mode = 0, uid = 0, gid = 0, nlink = 0, mtime = 0, filesize = 0, namesize = 0;
        if (!ParseHex8(hdr + 14, mode) ||
            !ParseHex8(hdr + 22, uid) ||
            !ParseHex8(hdr + 30, gid) ||
            !ParseHex8(hdr + 38, nlink) ||
            !ParseHex8(hdr + 46, mtime) ||
            !ParseHex8(hdr + 54, filesize) ||
            !ParseHex8(hdr + 94, namesize)) {
            out_error = "Invalid hex field in CPIO header";
            return false;
        }
        pos += 110u;

        if (namesize == 0u || namesize > bytes.size() - pos) {
            out_error = "CPIO entry name extends past EOF";
            return false;
        }
        std::string name(reinterpret_cast<const char*>(bytes.data() + pos), namesize - 1u);
        pos = Align4(pos + namesize);
        if (pos > bytes.size() || filesize > bytes.size() - pos) {
            out_error = "CPIO entry payload extends past EOF";
            return false;
        }

        if (name == "TRAILER!!!") {
            pos = Align4(pos + filesize);
            continue;
        }

        CpioEntry entry;
        entry.name = NormalizeCpioPath(name);
        entry.mode = mode;
        entry.uid = uid;
        entry.gid = gid;
        entry.nlink = nlink;
        entry.mtime = mtime;
        if (filesize > 0u) {
            entry.data.assign(bytes.begin() + static_cast<std::ptrdiff_t>(pos),
                              bytes.begin() + static_cast<std::ptrdiff_t>(pos + filesize));
        }
        pos = Align4(pos + filesize);

        if (!entry.name.empty() && entry.name != ".") {
            out_entries.push_back(std::move(entry));
        }
    }
    return true;
}

const CpioEntry* CpioArchive::FindEntry(const std::vector<CpioEntry>& entries,
                                        const std::string& path) {
    std::string target = NormalizeCpioPath(path);
    const CpioEntry* found = nullptr;
    // Later entries override earlier entries (matches Linux initramfs unpack semantics)
    for (const auto& e : entries) {
        if (NormalizeCpioPath(e.name) == target) {
            found = &e;
        }
    }
    return found;
}

std::vector<uint8_t> CpioArchive::Build(const std::vector<CpioEntry>& entries) {
    std::vector<uint8_t> out;
    uint32_t ino = 1u;

    auto append_entry = [&](const std::string& name,
                            uint32_t mode,
                            uint32_t uid,
                            uint32_t gid,
                            uint32_t nlink,
                            uint32_t mtime,
                            const std::vector<uint8_t>& data) {
        char hdr[111];
        std::snprintf(
            hdr, sizeof(hdr),
            "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
            ino++,
            mode,
            uid,
            gid,
            nlink,
            mtime,
            static_cast<uint32_t>(data.size()),
            0u, 0u, 0u, 0u,
            static_cast<uint32_t>(name.size() + 1u),
            0u);
        out.insert(out.end(), hdr, hdr + 110);
        out.insert(out.end(), name.begin(), name.end());
        out.push_back(0);
        while ((out.size() & 3u) != 0u) out.push_back(0);
        if (!data.empty()) {
            out.insert(out.end(), data.begin(), data.end());
            while ((out.size() & 3u) != 0u) out.push_back(0);
        }
    };

    for (const auto& e : entries) {
        std::string norm = NormalizeCpioPath(e.name);
        if (norm.empty()) continue;
        append_entry(norm, e.mode, e.uid, e.gid, e.nlink, e.mtime, e.data);
    }
    append_entry("TRAILER!!!", 0u, 0u, 0u, 1u, 0u, {});
    while ((out.size() & 511u) != 0u) out.push_back(0); // 512-byte CPIO block pad
    return out;
}

} // namespace haseeb::vm
