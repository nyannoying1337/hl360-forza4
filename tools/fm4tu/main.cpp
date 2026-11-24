// fm4tu - prepares an original Forza Motorsport 4 USA Disc 1 for the port.
//
// The port is built from the USA Rev 1 default.xex. The original USA pressing
// (media ID 26FF1101, XEX 0.0.0.8) plus Title Update 4 produces exactly the
// same code and data layout, so this tool applies the title update the way
// the Xbox 360 kernel does and writes a regular XEX2 file again.
//
//   fm4tu apply <game_dir> <title_update_package>
//       <game_dir> holds the extracted Disc 1 (default.xex, Media\...).
//       Replaces default.xex with the patched executable (the original is
//       kept as .fm4-tu\default.xex.base), places the update's
//       Media\tracks\LeMans\patch_bin.zip in the game folder, extracts the
//       whole package to TitleUpdate\ (mounted as update: by the game) and
//       verifies the protected game files against the patched executable.
//       On success it writes .fm4-tu\prepared, which the launcher looks for.
//
//   fm4tu check <game_dir>
//       Verifies a prepared folder without changing it.
//
// Every input and the result are checked against known SHA-256 values, so
// a wrong disc, a different update or a failed patch never goes unnoticed.

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#include "../../launcher/src/sha256.h"
#include "crypto.h"

extern "C" {
#include "lzx.h"
#include "mspack.h"
}

namespace fs = std::filesystem;
using fm4tu::Aes128;
using fm4tu::Sha1;
using Bytes = std::vector<uint8_t>;

namespace {

// Original USA Disc 1, media ID 26FF1101.
constexpr char kBaseXexSha256[] = "3618e85af83e972ddcc1b0d0dd808e78e29ab4ab3890a15b31c210a6a3e93e09";
constexpr char kBaseSpeechSha256[] = "b8a5e5137bb18ec42c7e0e2fe5b3e5e760e11e0b0d5ddf0098186995aa7c0f5e";
constexpr char kBaseXMediaSha256[] = "560bb53fc9a335399e82ba92121410e6781841cbabe3e9dfbf0de43dde7258e9";
// Title Update 4 package (tu00000008_00000000) and the executable it yields.
constexpr char kUpdateSha256[] = "bbc7c2317931b3cd74f2f321d9ad98ce6b63b894b5fc2d4a400957ce26654736";
constexpr char kPatchedXexSha256[] = "10556f93213204deb7cec88a9f1c8b3aabce83a33760baa20ee4475f3c467930";
constexpr char kPatchBinSha256[] = "c484dcc8770ce570e8b9cd1fcd6a30504421bf3599a8a4eadded3b7cae36a2f9";
// USA Rev 1 default.xex: nothing to do.
constexpr char kRev1XexSha256[] = "e0a93ee8a3e16dbb5c327b940efb38e9d125809a4281ab75cbfa9cd987285d4c";

constexpr uint8_t kRetailKey[16] = {0x20, 0xB1, 0x85, 0xA5, 0x9D, 0x28, 0xFD, 0xC3,
                                    0x40, 0x58, 0x3F, 0xBB, 0x08, 0x96, 0xBF, 0x91};
constexpr uint32_t kImageBase = 0x82000000;
constexpr uint32_t kSignatureTable = 0x82EA0000;  // see src/file_signatures.cpp
constexpr char kUpdateDir[] = "TitleUpdate";
constexpr char kStateDir[] = ".fm4-tu";
// Title updates keep one folder per disc; Disc 1's files are update:'s root.
constexpr char kDiscFolder[] = "disc001";

[[noreturn]] void Fail(const std::string& message) { throw std::runtime_error(message); }

uint32_t Be32(const uint8_t* p) { return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3]; }
uint16_t Be16(const uint8_t* p) { return uint16_t(p[0] << 8 | p[1]); }
uint32_t Le24(const uint8_t* p) { return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16; }

Bytes ReadFile(const fs::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) Fail("cannot read " + path.u8string());
  in.seekg(0, std::ios::end);
  Bytes data(size_t(in.tellg()));
  in.seekg(0);
  in.read(reinterpret_cast<char*>(data.data()), std::streamsize(data.size()));
  if (!in) Fail("cannot read " + path.u8string());
  return data;
}

// Writes through a temporary file so an interrupted run never leaves half a file.
void WriteFile(const fs::path& path, const uint8_t* data, size_t size) {
  fs::create_directories(path.parent_path());
  fs::path tmp = path;
  tmp += ".fm4tu-tmp";
  {
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(data), std::streamsize(size));
    if (!out) Fail("cannot write " + tmp.u8string());
  }
  std::error_code ec;
  fs::rename(tmp, path, ec);
  if (ec) {
    fs::remove(path, ec);
    fs::rename(tmp, path);
  }
}
void WriteFile(const fs::path& path, const Bytes& data) { WriteFile(path, data.data(), data.size()); }

std::string Sha256Hex(const uint8_t* data, size_t size) {
  launcher::Sha256 sha;
  sha.Update(data, size);
  return sha.HexDigest();
}
std::string Sha256Hex(const Bytes& data) { return Sha256Hex(data.data(), data.size()); }

std::string Lower(std::string s) {
  for (char& c : s) c = char(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

// Resolves a relative path one component at a time, ignoring case, so the
// tool behaves the same on case-sensitive file systems.
std::optional<fs::path> FindPath(const fs::path& root, const std::string& relative) {
  fs::path current = root;
  std::string rel = relative;
  std::replace(rel.begin(), rel.end(), '\\', '/');
  size_t pos = 0;
  while (pos <= rel.size()) {
    const size_t next = rel.find('/', pos);
    const std::string part = rel.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
    if (!part.empty()) {
      if (fs::exists(current / part)) {
        current /= part;
      } else {
        bool found = false;
        std::error_code ec;
        for (const auto& entry : fs::directory_iterator(current, ec)) {
          if (Lower(entry.path().filename().u8string()) == Lower(part)) {
            current = entry.path();
            found = true;
            break;
          }
        }
        if (!found) return std::nullopt;
      }
    }
    if (next == std::string::npos) break;
    pos = next + 1;
  }
  return current;
}

// ---------------------------------------------------------------------------
// LZX delta (libmspack), as used by XEX2 patches.

struct MemFile {
  uint8_t* data;
  size_t size;
  size_t offset;
};
int MemRead(mspack_file* f, void* buffer, int bytes) {
  auto* m = reinterpret_cast<MemFile*>(f);
  const size_t n = std::min(size_t(bytes), m->size - m->offset);
  std::memcpy(buffer, m->data + m->offset, n);
  m->offset += n;
  return int(n);
}
int MemWrite(mspack_file* f, void* buffer, int bytes) {
  auto* m = reinterpret_cast<MemFile*>(f);
  const size_t n = std::min(size_t(bytes), m->size - m->offset);
  std::memcpy(m->data + m->offset, buffer, n);
  m->offset += n;
  return int(n);
}
void* MemAlloc(mspack_system*, size_t bytes) { return std::calloc(bytes, 1); }
void MemFree(void* p) { std::free(p); }
void MemCopy(void* src, void* dst, size_t bytes) { std::memmove(dst, src, bytes); }
void MemMessage(mspack_file*, const char*, ...) {}

void LzxDecompress(const uint8_t* src, size_t src_len, uint8_t* dst, size_t dst_len, uint32_t window_size,
                   const uint8_t* reference, size_t reference_len) {
  mspack_system sys{};
  sys.read = MemRead;
  sys.write = MemWrite;
  sys.alloc = MemAlloc;
  sys.free = MemFree;
  sys.copy = MemCopy;
  sys.message = MemMessage;
  MemFile in{const_cast<uint8_t*>(src), src_len, 0};
  MemFile out{dst, dst_len, 0};
  int bits = 0;
  while ((1u << bits) < window_size) ++bits;
  lzxd_stream* lzx = lzxd_init(&sys, reinterpret_cast<mspack_file*>(&in), reinterpret_cast<mspack_file*>(&out), bits,
                               0, 0x8000, off_t(dst_len), 0);
  if (!lzx) Fail("LZX decoder initialisation failed");
  // The old data is the dictionary: zero-padded and placed at the window's end.
  const Bytes ref(reference, reference + reference_len);
  std::memset(lzx->window, 0, window_size - reference_len);
  std::memcpy(lzx->window + (window_size - reference_len), ref.data(), reference_len);
  lzx->ref_data_size = window_size;
  const int result = lzxd_decompress(lzx, off_t(dst_len));
  lzxd_free(lzx);
  if (result != MSPACK_ERR_OK) Fail("LZX delta decompression failed (" + std::to_string(result) + ")");
}

// Applies a chain of xex2_delta_patch records to `dest`.
void ApplyDeltaChain(const uint8_t* patch, size_t patch_len, uint32_t window_size, Bytes& dest) {
  size_t pos = 0;
  while (pos + 12 <= patch_len) {
    const uint32_t old_addr = Be32(patch + pos), new_addr = Be32(patch + pos + 4);
    const uint16_t uncompressed = Be16(patch + pos + 8), compressed = Be16(patch + pos + 10);
    if (!old_addr && !new_addr && !uncompressed && !compressed) break;
    if (size_t(new_addr) + uncompressed > dest.size() || size_t(old_addr) + uncompressed > dest.size())
      Fail("patch record outside the image");
    size_t record = 12;
    if (compressed == 0) {
      std::memset(dest.data() + new_addr, 0, uncompressed);
    } else if (compressed == 1) {
      std::memmove(dest.data() + new_addr, dest.data() + old_addr, uncompressed);
    } else {
      if (pos + 12 + compressed > patch_len) Fail("truncated patch record");
      LzxDecompress(patch + pos + 12, compressed, dest.data() + new_addr, uncompressed, window_size,
                    dest.data() + old_addr, uncompressed);
      record += compressed;
    }
    pos += record;
  }
}

// ---------------------------------------------------------------------------
// XEX2

struct Xex {
  Bytes file;
  uint32_t header_size = 0;
  uint32_t security = 0;
  std::map<uint32_t, uint32_t> headers;  // optional header key -> value/offset

  explicit Xex(Bytes data) : file(std::move(data)) {
    if (file.size() < 0x18 || std::memcmp(file.data(), "XEX2", 4) != 0) Fail("not an XEX2 file");
    header_size = Be32(&file[8]);
    security = Be32(&file[0x10]);
    const uint32_t count = Be32(&file[0x14]);
    if (header_size > file.size() || 0x18 + size_t(count) * 8 > header_size) Fail("malformed XEX2 header");
    for (uint32_t i = 0; i < count; ++i) headers[Be32(&file[0x18 + i * 8])] = Be32(&file[0x1C + i * 8]);
  }
  const uint8_t* Opt(uint32_t key) const {
    auto it = headers.find(key);
    if (it == headers.end() || it->second >= header_size) Fail("XEX2 optional header missing");
    return &file[it->second];
  }
  // Session key: the header's file key decrypted with `parent`.
  void SessionKey(const uint8_t parent[16], uint8_t out[16]) const {
    Aes128(parent).DecryptBlock(&file[security + 0x150], out);
  }
};

struct FileFormat {
  uint16_t encryption, compression;
  const uint8_t* info;  // xex2_opt_file_format_info
  uint32_t info_size;
};
FileFormat Format(const Bytes& header, uint32_t offset) {
  const uint8_t* p = &header[offset];
  return {Be16(p + 4), Be16(p + 6), p, Be32(p)};
}

// Decrypted, decompressed memory image of a basic-compressed retail XEX.
Bytes LoadImage(const Xex& xex) {
  const FileFormat ff = Format(xex.file, xex.headers.at(0x3FF));
  if (ff.compression != 1) Fail("unsupported XEX compression " + std::to_string(ff.compression));
  Bytes payload(xex.file.begin() + xex.header_size, xex.file.end());
  if (ff.encryption == 1) {
    uint8_t key[16];
    xex.SessionKey(kRetailKey, key);
    Aes128(key).CbcDecrypt(payload.data(), payload.size());
  }
  Bytes image;
  size_t pos = 0;
  for (uint32_t i = 0; i < (ff.info_size - 8) / 8; ++i) {
    const uint32_t data_size = Be32(ff.info + 8 + i * 8), zero_size = Be32(ff.info + 12 + i * 8);
    if (pos + data_size > payload.size()) Fail("XEX payload is truncated");
    image.insert(image.end(), payload.begin() + pos, payload.begin() + pos + data_size);
    image.insert(image.end(), zero_size, 0);
    pos += data_size;
  }
  if (image.size() < 2 || image[0] != 'M' || image[1] != 'Z') Fail("XEX decryption failed");
  return image;
}

// Applies `patch` (an .xexp) to `base`; returns the patched header and image.
std::pair<Bytes, Bytes> ApplyXexp(const Xex& base, const Xex& patch) {
  const uint8_t* desc = patch.Opt(0x5FF);  // xex2_opt_delta_patch_descriptor
  const uint32_t desc_size = Be32(desc);
  const uint32_t target_headers = Be32(desc + 0x30), hdr_src_off = Be32(desc + 0x34),
                 hdr_src_size = Be32(desc + 0x38), hdr_dst_off = Be32(desc + 0x3C),
                 img_src_off = Be32(desc + 0x40), img_src_size = Be32(desc + 0x44), img_dst_off = Be32(desc + 0x48);

  // The patch must belong to this exact base executable.
  uint8_t digest[20];
  Sha1(&base.file[base.security + 8], 0x100, digest);
  if (std::memcmp(digest, desc + 0x0C, 20) != 0) Fail("the title update is not for this default.xex");

  const FileFormat pff = Format(patch.file, patch.headers.at(0x3FF));
  if (pff.compression != 3) Fail("the update's default.xexp is not a delta patch");
  const uint32_t window = Be32(pff.info + 8);

  uint8_t base_key[16];
  base.SessionKey(kRetailKey, base_key);
  const uint32_t base_image_size = Be32(&base.file[base.security + 4]);

  // Header delta.
  Bytes header(base.file.begin(), base.file.begin() + base.header_size);
  const uint32_t header_target = target_headers ? target_headers : hdr_dst_off + hdr_src_size;
  if (hdr_src_off > header.size() || hdr_src_size > header.size() - hdr_src_off) Fail("bad header patch");
  if (header_target > header.size()) header.resize(header_target, 0);
  if (hdr_src_off) std::memmove(&header[hdr_dst_off], &header[hdr_src_off], hdr_src_size);
  if (header_target < header.size()) std::fill(header.begin() + header_target, header.end(), 0);
  ApplyDeltaChain(desc + 0x4C, desc_size - 0x4C, window, header);
  header.resize(header_target);

  Xex patched_header(header);
  const uint32_t new_image_size = Be32(&header[patched_header.security + 4]);
  uint8_t new_base_key[16], patch_key[16], check[16];
  patched_header.SessionKey(kRetailKey, new_base_key);
  Aes128(new_base_key).DecryptBlock(&patch.file[patch.security + 0x150], patch_key);
  Aes128(new_base_key).DecryptBlock(desc + 0x20, check);
  if (std::memcmp(check, base_key, 16) != 0) Fail("title update image key does not match the base XEX");

  // Image delta, block by block.
  Bytes image = LoadImage(base);
  image.resize(std::max<size_t>(image.size(), new_image_size), 0);
  if (img_src_off) std::memmove(&image[img_dst_off], &image[img_src_off], img_src_size);
  const uint32_t image_target = img_dst_off + img_src_size;
  if (image_target < base_image_size) std::fill(image.begin() + image_target, image.begin() + base_image_size, 0);

  Bytes data(patch.file.begin() + patch.header_size, patch.file.end());
  if (pff.encryption == 1) Aes128(patch_key).CbcDecrypt(data.data(), data.size());
  uint32_t block_size = Be32(pff.info + 12);
  const uint8_t* block_hash = pff.info + 16;
  size_t pos = 0;
  while (block_size) {
    if (pos + block_size > data.size() || block_size < 24) Fail("title update data is truncated");
    Sha1(&data[pos], block_size, digest);
    if (std::memcmp(digest, block_hash, 20) != 0) Fail("title update block hash mismatch");
    const uint32_t next_size = Be32(&data[pos]);
    const uint8_t* next_hash = &data[pos + 4];
    ApplyDeltaChain(&data[pos + 24], block_size - 24, window, image);
    block_hash = next_hash;
    pos += block_size;
    block_size = next_size;
  }
  image.resize(new_image_size);
  return {header, image};
}

// Re-encrypts a patched image into an XEX2 file with the patched header.
Bytes BuildXex(const Bytes& header, const Bytes& image) {
  const Xex xex(header);
  const FileFormat ff = Format(header, xex.headers.at(0x3FF));
  if (ff.compression != 1) Fail("patched XEX does not use basic compression");
  Bytes out(header.begin(), header.begin() + xex.header_size);
  size_t pos = 0;
  for (uint32_t i = 0; i < (ff.info_size - 8) / 8; ++i) {
    const uint32_t data_size = Be32(ff.info + 8 + i * 8), zero_size = Be32(ff.info + 12 + i * 8);
    if (pos + data_size > image.size()) Fail("patched image is smaller than its block list");
    out.insert(out.end(), image.begin() + pos, image.begin() + pos + data_size);
    pos += data_size + zero_size;
  }
  if (ff.encryption == 1) {
    uint8_t key[16];
    xex.SessionKey(kRetailKey, key);
    Aes128(key).CbcEncrypt(out.data() + xex.header_size, out.size() - xex.header_size);
  }
  return out;
}

// ---------------------------------------------------------------------------
// STFS (read-only LIVE/PIRS packages with contiguous files, as title updates are)

struct StfsFile {
  std::string path;  // '/' separated
  uint32_t start_block, blocks, size;
};

class Stfs {
 public:
  explicit Stfs(Bytes data) : data_(std::move(data)) {
    if (data_.size() < 0x1000 ||
        (std::memcmp(data_.data(), "LIVE", 4) != 0 && std::memcmp(data_.data(), "PIRS", 4) != 0))
      Fail("not a LIVE/PIRS package");
    header_size_ = Be32(&data_[0x340]);
    content_type_ = Be32(&data_[0x344]);
    media_id_ = Be32(&data_[0x354]);
    title_id_ = Be32(&data_[0x360]);
    if (data_[0x379] != 0x24) Fail("unsupported package volume");
    shift_ = (data_[0x37B] & 1) ? 0 : 1;
    const uint32_t table_blocks = data_[0x37C] | data_[0x37D] << 8;
    const uint32_t table_block = Le24(&data_[0x37E]);
    struct Raw {
      std::string name;
      uint16_t parent;
      bool dir;
      StfsFile file;
    };
    std::vector<Raw> raw;
    for (uint32_t b = 0; b < table_blocks; ++b) {
      const size_t base = Offset(table_block + b);
      if (base + 0x1000 > data_.size()) Fail("package is truncated");
      for (int i = 0; i < 64; ++i) {
        const uint8_t* e = &data_[base + i * 0x40];
        if (!e[0]) break;
        const uint8_t flags = e[0x28];
        Raw r{std::string(reinterpret_cast<const char*>(e), std::min<size_t>(flags & 0x3F, 0x28)), Be16(e + 0x32),
              (flags & 0x80) != 0, {}};
        if (!r.dir) {
          if (!(flags & 0x40)) Fail("fragmented package files are not supported");
          r.file = {"", Le24(e + 0x2F), Le24(e + 0x29), Be32(e + 0x34)};
        }
        raw.push_back(std::move(r));
      }
    }
    for (const Raw& r : raw) {
      if (r.dir) continue;
      std::string path = r.name;
      uint16_t parent = r.parent;
      for (int depth = 0; parent != 0xFFFF; ++depth) {
        if (parent >= raw.size() || depth > 32) Fail("bad package directory index");
        path = raw[parent].name + "/" + path;
        parent = raw[parent].parent;
      }
      StfsFile f = r.file;
      f.path = path;
      for (const std::string& part : {std::string("..")})
        if (path.find(part) != std::string::npos) Fail("unsafe path in package: " + path);
      files_.push_back(f);
    }
  }

  uint32_t content_type() const { return content_type_; }
  uint32_t media_id() const { return media_id_; }
  uint32_t title_id() const { return title_id_; }

  const std::vector<StfsFile>& Files() const { return files_; }

  Bytes Read(const StfsFile& f) const {
    Bytes out;
    out.reserve(f.size);
    for (uint32_t i = 0; i < f.blocks && out.size() < f.size; ++i) {
      const size_t off = Offset(f.start_block + i);
      if (off + 0x1000 > data_.size()) Fail("package is truncated");
      const size_t n = std::min<size_t>(0x1000, f.size - out.size());
      out.insert(out.end(), data_.begin() + off, data_.begin() + off + n);
    }
    if (out.size() != f.size) Fail("package file is truncated: " + f.path);
    return out;
  }

  const StfsFile* Find(const std::string& path) const {
    for (const StfsFile& f : files_)
      if (Lower(f.path) == Lower(path)) return &f;
    return nullptr;
  }

 private:
  // Data block number -> file offset, skipping the interleaved hash tables.
  size_t Offset(uint32_t block) const {
    uint32_t base = ((block + 0xAA) / 0xAA) << shift_;
    if (block >= 0xAA) {
      base += ((block + 0x70E4) / 0x70E4) << shift_;
      if (block >= 0x70E4) base += 1u << shift_;
    }
    return size_t((header_size_ + 0xFFF) & ~0xFFFu) + size_t(base + block) * 0x1000;
  }

  Bytes data_;
  uint32_t header_size_ = 0, content_type_ = 0, media_id_ = 0, title_id_ = 0;
  int shift_ = 0;
  std::vector<StfsFile> files_;
};

// ---------------------------------------------------------------------------
// Protected-file table inside the executable (SHA-256 per 32 KiB block).

int CheckProtectedFiles(const Bytes& image, const fs::path& game_dir) {
  const size_t table = kSignatureTable - kImageBase;
  if (image.size() < table + 8) Fail("signature table is outside the image");
  const uint8_t* t = &image[table];
  const uint32_t block = Be32(t), count = Be32(t + 4);
  if (block != 0x8000 || count == 0 || count > 1024) Fail("unexpected signature table");
  const size_t data_start = 8 + size_t(count) * 8;
  int bad = 0, skipped = 0;
  for (uint32_t i = 0; i < count; ++i) {
    const uint32_t offset = Be32(t + 8 + i * 8), size = Be32(t + 12 + i * 8);
    const char* name = reinterpret_cast<const char*>(t + data_start + offset);
    const std::string rel(name, strnlen(name, 128));
    const uint8_t* hashes = t + data_start + offset + rel.size() + 1;
    // The launcher rewrites these for its graphics options (and checks them itself).
    if (Lower(rel).rfind("media\\renderscenarios\\", 0) == 0) {
      ++skipped;
      continue;
    }
    const auto path = FindPath(game_dir, rel);
    if (!path) {
      std::fprintf(stderr, "  missing protected file: %s\n", rel.c_str());
      ++bad;
      continue;
    }
    const Bytes data = ReadFile(*path);
    bool ok = data.size() == size;
    for (size_t pos = 0, n = 0; ok && (pos < data.size() || (data.empty() && n == 0)); pos += 0x8000, ++n) {
      const size_t len = std::min<size_t>(0x8000, data.size() - pos);
      launcher::Sha256 sha;
      sha.Update(data.data() + pos, len);
      std::string hex = sha.HexDigest();
      char expected[65];
      for (int k = 0; k < 32; ++k) std::snprintf(expected + k * 2, 3, "%02x", hashes[n * 32 + k]);
      ok = hex == expected;
      if (data.empty()) break;
    }
    if (!ok) {
      std::fprintf(stderr, "  protected file differs: %s\n", rel.c_str());
      ++bad;
    }
  }
  std::printf("protected files: %u checked, %d differ (%d render scenarios left to the launcher)\n",
              count - skipped, bad, skipped);
  return bad;
}

std::string HashFileHex(const fs::path& path) { return Sha256Hex(ReadFile(path)); }

void RequireHash(const fs::path& path, const char* expected, const char* what) {
  const std::string actual = HashFileHex(path);
  if (actual != expected) Fail(std::string(what) + " does not match (SHA-256 " + actual + ")");
}

int Check(const fs::path& game_dir) {
  const auto xex_path = FindPath(game_dir, "default.xex");
  if (!xex_path) Fail("default.xex not found in " + game_dir.u8string());
  const std::string hash = HashFileHex(*xex_path);
  if (hash == kRev1XexSha256) {
    std::printf("default.xex is USA Rev 1: no title update needed.\n");
    return 0;
  }
  if (hash != kPatchedXexSha256) {
    std::fprintf(stderr, "default.xex is not prepared (SHA-256 %s)\n", hash.c_str());
    return 1;
  }
  int bad = 0;
  const std::pair<const char*, const char*> facades[] = {{"SpeechFacade_default.xex", kBaseSpeechSha256},
                                                         {"XMediaFacade_default.xex", kBaseXMediaSha256}};
  for (const auto& [name, expected] : facades) {
    const auto p = FindPath(game_dir, name);
    if (!p || HashFileHex(*p) != expected) {
      std::fprintf(stderr, "  %s does not match the original USA disc\n", name);
      ++bad;
    }
  }
  const auto patch_bin = FindPath(game_dir, "Media/tracks/LeMans/patch_bin.zip");
  if (!patch_bin || HashFileHex(*patch_bin) != kPatchBinSha256) {
    std::fprintf(stderr, "  Media\\tracks\\LeMans\\patch_bin.zip is missing or different\n");
    ++bad;
  }
  if (!FindPath(game_dir, std::string(kUpdateDir) + "/media.zip")) {
    std::fprintf(stderr, "  %s\\media.zip is missing\n", kUpdateDir);
    ++bad;
  }
  bad += CheckProtectedFiles(LoadImage(Xex(ReadFile(*xex_path))), game_dir);
  std::printf(bad ? "check failed\n" : "game folder is ready (USA Disc 1 + Title Update 4)\n");
  return bad ? 1 : 0;
}

int Apply(const fs::path& game_dir, const fs::path& update_path) {
  const auto xex_path = FindPath(game_dir, "default.xex");
  if (!xex_path) Fail("default.xex not found in " + game_dir.u8string());

  const Bytes package_data = ReadFile(update_path);
  const std::string package_hash = Sha256Hex(package_data);
  if (package_hash != kUpdateSha256)
    Fail("this is not the supported Title Update 4 package (SHA-256 " + package_hash + ")");
  const Stfs package(package_data);
  if (package.content_type() != 0x000B0000 || package.title_id() != 0x4D530910 || package.media_id() != 0x26FF1101)
    Fail("the package is not the FM4 USA title update");

  Bytes current = ReadFile(*xex_path);
  const std::string current_hash = Sha256Hex(current);
  if (current_hash == kRev1XexSha256) {
    std::printf("default.xex is already USA Rev 1; no title update needed.\n");
    return 0;
  }
  if (current_hash == kPatchedXexSha256) {
    std::printf("default.xex is already patched.\n");
  } else {
    if (current_hash != kBaseXexSha256)
      Fail("default.xex is not from the original USA disc (SHA-256 " + current_hash + ")");
    RequireHash(*FindPath(game_dir, "SpeechFacade_default.xex"), kBaseSpeechSha256, "SpeechFacade_default.xex");
    RequireHash(*FindPath(game_dir, "XMediaFacade_default.xex"), kBaseXMediaSha256, "XMediaFacade_default.xex");

    const StfsFile* xexp = package.Find(std::string(kDiscFolder) + "/default.xexp");
    if (!xexp) Fail("default.xexp not found in the title update");
    const Xex base(current);
    const Xex patch(package.Read(*xexp));
    auto [header, image] = ApplyXexp(base, patch);
    const Bytes patched = BuildXex(header, image);
    const std::string patched_hash = Sha256Hex(patched);
    if (patched_hash != kPatchedXexSha256) Fail("patched default.xex has an unexpected SHA-256 " + patched_hash);
    WriteFile(game_dir / kStateDir / "default.xex.base", current);
    WriteFile(*xex_path, patched);
    current = patched;
    std::printf("default.xex patched to Title Update 4 (SHA-256 %s)\n", patched_hash.c_str());
  }

  // Disc 1's update files: all of them under TitleUpdate\ for update:, and
  // patch_bin.zip where its tu_mount.xml looks for it (game:\Media\...).
  const std::string prefix = std::string(kDiscFolder) + "/";
  size_t written = 0;
  for (const StfsFile& f : package.Files()) {
    if (Lower(f.path).rfind(prefix, 0) != 0) continue;
    const std::string rel = f.path.substr(prefix.size());
    const Bytes data = package.Read(f);
    WriteFile(game_dir / kUpdateDir / fs::u8path(rel), data);
    ++written;
    if (Lower(rel) == "media/tracks/lemans/patch_bin.zip") {
      if (Sha256Hex(data) != kPatchBinSha256) Fail("unexpected patch_bin.zip in the title update");
      WriteFile(game_dir / "Media" / "tracks" / "LeMans" / "patch_bin.zip", data);
    }
  }
  std::printf("title update files: %zu extracted to %s\n", written, (game_dir / kUpdateDir).u8string().c_str());
  const int result = Check(game_dir);
  // The launcher verifies folders with this marker against the USA + TU4 manifest.
  const std::string marker = "USA Disc 1 (26FF1101) + Title Update 4\n";
  if (result == 0) WriteFile(game_dir / kStateDir / "prepared", reinterpret_cast<const uint8_t*>(marker.data()), marker.size());
  return result;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const std::string cmd = argc > 1 ? argv[1] : "";
    if (cmd == "apply" && argc == 4) return Apply(fs::u8path(argv[2]), fs::u8path(argv[3]));
    if (cmd == "check" && argc == 3) return Check(fs::u8path(argv[2]));
    std::fprintf(stderr,
                 "usage: fm4tu apply <game_dir> <title_update_package>\n"
                 "       fm4tu check <game_dir>\n");
    return 2;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "error: %s\n", e.what());
    return 1;
  }
}
