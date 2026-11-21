#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace haseeb::vm {

struct CpioEntry {
    std::string name;
    uint32_t mode = 0100755u;
    uint32_t uid = 0;
    uint32_t gid = 0;
    uint32_t nlink = 1;
    uint32_t mtime = 0;
    std::vector<uint8_t> data;

    bool IsDirectory() const { return (mode & 0170000u) == 0040000u; }
    bool IsRegular() const { return (mode & 0170000u) == 0100000u; }
    bool IsSymlink() const { return (mode & 0170000u) == 0120000u; }
};

// From-scratch SVR4 newc ('070701' / '070702') CPIO initramfs parser and builder
class CpioArchive {
public:
    static bool LooksLikeNewc(const std::vector<uint8_t>& bytes);

    static bool Parse(const std::vector<uint8_t>& bytes,
                      std::vector<CpioEntry>& out_entries,
                      std::string& out_error);

    static const CpioEntry* FindEntry(const std::vector<CpioEntry>& entries,
                                      const std::string& path);

    static std::vector<uint8_t> Build(const std::vector<CpioEntry>& entries);
};

} // namespace haseeb::vm
