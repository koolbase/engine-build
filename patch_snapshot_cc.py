#!/usr/bin/env python3
#
# Koolbase System B #1 — whole-blob snapshot replacement.
#
# Injects into dart_snapshot.cc (NOT dart_isolate.cc — that is the marker
# injector patch_dart_cc.py). This intercepts IsolateSnapshotFromSettings, the
# single seam where the engine hands the isolate's data+instructions mappings to
# Dart. When a verified whole-blob patch is staged, we reconstruct the snapshot
# into fresh buffers (instructions into MAP_JIT executable memory) and build the
# DartSnapshot from those via the engine's own IsolateSnapshotFromMappings()
# factory. Dart creates the isolate from our blob and never knows the difference.
#
# IDENTITY MILESTONE: reconstruction is a byte-for-byte copy of the base blobs
# (no diff applied). If the app runs from these copies, seam + exec memory +
# supply path are proven; a real diff is just non-identity bytes in MakeExecCopy
# / the data memcpy.
#
# Whole-blob patch header (128-byte KBPM frame, signed [0..63]):
#   [0..3]    "KBPM"
#   [8]       kind = 2  (2 = whole-blob; marker patches leave this 0)
#   [16..23]  build_id (first 8 bytes of SHA-256 over base instructions)
#   [24..31]  base_data_size  (little-endian u64)   <- NEW for whole-blob
#   [56..63]  base_instr_size (little-endian u64)   <- same field as marker
#   [64..127] Ed25519 signature over [0..63]

target_path = "engine/src/flutter/runtime/dart_snapshot.cc"

with open(target_path, 'r') as f:
    content = f.read()

# ---- 1. includes -----------------------------------------------------------
include_marker = '#include "flutter/runtime/dart_vm.h"'
include_addition = include_marker + '''
#include "flutter/fml/mapping.h"
#include <cstdio>
#include <cstdarg>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <memory>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <libkern/OSCacheControl.h>'''
if include_marker not in content:
    print("ERROR: include marker not found")
    exit(1)
content = content.replace(include_marker, include_addition, 1)

# ---- 2. helpers + reconstruction (injected at top of namespace flutter) ----
koolbase_code = '''

static void kb_log(const char* fmt, ...) {
  FILE* f = fopen("/tmp/koolbase_log.txt", "a");
  if (!f) return;
  va_list args;
  va_start(args, fmt);
  vfprintf(f, fmt, args);
  va_end(args);
  fputc('\\n', f);
  fclose(f);
}

// BoringSSL is linked into the engine; forward-declare with C linkage to avoid
// the openssl include chain in this TU (same pattern as the marker injector).
extern "C" int ED25519_verify(const uint8_t* message, size_t message_len,
                              const uint8_t signature[64],
                              const uint8_t public_key[32]);
extern "C" uint8_t* SHA256(const uint8_t* data, size_t len, uint8_t* out);

static const uint8_t koolbase_pubkey[32] = {
  0xba, 0x16, 0xbb, 0x70, 0x5e, 0xf2, 0xd1, 0x84, 0x08, 0xe7, 0xae, 0xd9,
  0xa7, 0x69, 0x52, 0xdc, 0xbd, 0x9b, 0xec, 0x47, 0x37, 0xff, 0x1b, 0xa5,
  0x58, 0x84, 0x65, 0x34, 0x81, 0x24, 0x26, 0xcb
};

static uint64_t Koolbase_ReadU64(const uint8_t* p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v |= ((uint64_t)p[i]) << (8 * i);
  return v;
}

static bool Koolbase_VerifySignature(const uint8_t* patch) {
  int ok = ED25519_verify(patch, 64, patch + 64, koolbase_pubkey);
  if (ok == 1) { kb_log("signature VERIFIED"); return true; }
  kb_log("signature INVALID (ED25519_verify returned %d)", ok);
  return false;
}

static bool Koolbase_VerifyBuildId(const uint8_t* patch,
                                   const uint8_t* instructions) {
  uint64_t instr_size = Koolbase_ReadU64(patch + 56);
  if (instructions == nullptr || instr_size == 0) {
    kb_log("build_id check FAILED: instructions=%p size=%llu",
           instructions, (unsigned long long)instr_size);
    return false;
  }
  uint8_t digest[32];
  SHA256(instructions, (size_t)instr_size, digest);
  for (int i = 0; i < 8; i++) {
    if (digest[i] != patch[16 + i]) {
      kb_log("build_id MISMATCH at byte %d: got %02x want %02x",
             i, digest[i], patch[16 + i]);
      return false;
    }
  }
  kb_log("build_id VERIFIED (instr_size=%llu)", (unsigned long long)instr_size);
  return true;
}

static bool Koolbase_VmPath(const char* leaf, char* out, size_t out_len) {
  const char* home = getenv("HOME");
  if (!home) { kb_log("no HOME env"); return false; }
  snprintf(out, out_len,
           "%s/Library/Application Support/koolbase/vm/%s", home, leaf);
  return true;
}

static bool Koolbase_ReadStagedPatch(uint8_t* buf, size_t buf_len) {
  char path[1024];
  if (!Koolbase_VmPath("staged.kbpatch", path, sizeof(path))) return false;
  FILE* f = fopen(path, "rb");
  if (!f) { kb_log("no staged patch at %s", path); return false; }
  size_t got = fread(buf, 1, buf_len, f);
  fclose(f);
  if (got < buf_len) { kb_log("staged patch too short: %zu bytes", got); return false; }
  kb_log("read %zu staged bytes from %s", buf_len, path);
  return true;
}

static void Koolbase_MarkApplied() {
  char src[1024], dst[1024];
  if (!Koolbase_VmPath("staged.kbpatch", src, sizeof(src))) return;
  if (!Koolbase_VmPath("applied.kbpatch", dst, sizeof(dst))) return;
  if (rename(src, dst) == 0) kb_log("renamed staged -> applied");
  else kb_log("rename staged->applied failed errno=%d", errno);
}

// Allocate executable memory and copy `len` reconstructed instruction bytes
// into it (MAP_JIT W^X dance — proven on Apple Silicon via the jittest probe).
//
// pthread_jit_write_protect_np is macOS 11+; the engine's deployment target is
// 10.14 and compiles -Werror -Wunguarded-availability-new, so the call must be
// guarded. arm64 macOS is always 11+, so the guarded path runs on every real
// device; the __builtin_available check is purely to satisfy the 10.14 compiler.
static const uint8_t* Koolbase_MakeExecCopy(const uint8_t* src, size_t len) {
  void* mem = mmap(nullptr, len, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
  if (mem == MAP_FAILED) { kb_log("exec mmap failed errno=%d", errno); return nullptr; }
  if (__builtin_available(macOS 11.0, *)) {
    pthread_jit_write_protect_np(0);   // make MAP_JIT pages writable
    memcpy(mem, src, len);             // (identity copy; real diff applied here)
    pthread_jit_write_protect_np(1);   // make them executable
  } else {
    memcpy(mem, src, len);             // pre-11 (Intel): MAP_JIT is directly RWX
  }
  sys_icache_invalidate(mem, len);
  kb_log("exec copy %zu bytes -> %p", len, mem);
  return (const uint8_t*)mem;
}

// Build a replacement isolate snapshot from a verified staged whole-blob patch.
// Returns nullptr to fall back to the embedded snapshot (no patch / bad magic /
// wrong kind / verification failure / allocation failure).
static fml::RefPtr<DartSnapshot> Koolbase_TryBuildPatchedSnapshot(
    const std::shared_ptr<const fml::Mapping>& base_data,
    const std::shared_ptr<const fml::Mapping>& base_instr) {
  uint8_t patch[128];
  if (!Koolbase_ReadStagedPatch(patch, 128)) return nullptr;
  if (!(patch[0]=='K'&&patch[1]=='B'&&patch[2]=='P'&&patch[3]=='M')) {
    kb_log("invalid magic"); return nullptr;
  }
  if (patch[8] != 2) {  // kind 2 = whole-blob; anything else isn't ours
    kb_log("not a whole-blob patch (kind=%d), falling back", patch[8]);
    return nullptr;
  }

  const uint8_t* base_instr_ptr = base_instr->GetMapping();
  const uint8_t* base_data_ptr  = base_data->GetMapping();
  uint64_t base_instr_len = Koolbase_ReadU64(patch + 56);
  uint64_t base_data_len  = Koolbase_ReadU64(patch + 24);

  if (!Koolbase_VerifySignature(patch))            { kb_log("REJECTED: signature"); return nullptr; }
  if (!Koolbase_VerifyBuildId(patch, base_instr_ptr)) { kb_log("REJECTED: build_id"); return nullptr; }
  if (base_data_ptr == nullptr || base_data_len == 0) {
    kb_log("REJECTED: base data ptr=%p len=%llu",
           base_data_ptr, (unsigned long long)base_data_len);
    return nullptr;
  }

  // ---- reconstruct (identity milestone: new == base) ----
  uint64_t new_instr_len = base_instr_len;   // real diff: read from header
  uint64_t new_data_len  = base_data_len;

  const uint8_t* new_instr = Koolbase_MakeExecCopy(base_instr_ptr, new_instr_len);
  if (!new_instr) return nullptr;

  uint8_t* new_data = (uint8_t*)malloc(new_data_len);
  if (!new_data) { kb_log("data malloc failed"); return nullptr; }
  memcpy(new_data, base_data_ptr, new_data_len);

  // NonOwnedMapping(ptr, size, release_proc, dontneed_safe). release_proc is
  // null: these buffers intentionally live for the process lifetime.
  auto instr_map = std::make_shared<fml::NonOwnedMapping>(
      new_instr, new_instr_len, nullptr, false);
  auto data_map = std::make_shared<fml::NonOwnedMapping>(
      new_data, new_data_len, nullptr, false);

  auto snapshot = DartSnapshot::IsolateSnapshotFromMappings(data_map, instr_map);
  if (!snapshot) { kb_log("IsolateSnapshotFromMappings returned null"); return nullptr; }

  kb_log("** Koolbase: isolate from RECONSTRUCTED snapshot (instr=%llu data=%llu) **",
         (unsigned long long)new_instr_len, (unsigned long long)new_data_len);
  Koolbase_MarkApplied();
  return snapshot;
}
'''
ns_marker = 'namespace flutter {'
if ns_marker not in content:
    print("ERROR: namespace marker not found")
    exit(1)
content = content.replace(ns_marker, ns_marker + koolbase_code, 1)

# ---- 3. interception (anchor on the unique TRACE_EVENT0 line) --------------
hook_anchor = '  TRACE_EVENT0("flutter", "DartSnapshot::IsolateSnapshotFromSettings");'
hook_addition = hook_anchor + '''

  // ==== KOOLBASE WHOLE-BLOB HOOK (System B #1) ====
  {
    { FILE* kbf = fopen("/tmp/koolbase_log.txt", "w"); if (kbf) fclose(kbf); }
    auto kb_base_data = ResolveIsolateData(settings);
    auto kb_base_instr = ResolveIsolateInstructions(settings);
    kb_log("IsolateSnapshotFromSettings: base_data=%p base_instr=%p",
           kb_base_data ? kb_base_data->GetMapping() : nullptr,
           kb_base_instr ? kb_base_instr->GetMapping() : nullptr);
    if (kb_base_data && kb_base_instr) {
      fml::RefPtr<const DartSnapshot> kb_patched =
          Koolbase_TryBuildPatchedSnapshot(kb_base_data, kb_base_instr);
      if (kb_patched) {
        kb_log("using RECONSTRUCTED isolate snapshot");
        return kb_patched;
      }
    }
  }
  // ==== END KOOLBASE ====
  // (Fall through to the original embedded-snapshot path below.)'''
if hook_anchor not in content:
    print("ERROR: hook anchor (IsolateSnapshotFromSettings TRACE_EVENT0) not found")
    exit(1)
content = content.replace(hook_anchor, hook_addition, 1)

with open(target_path, 'w') as f:
    f.write(content)

print("Koolbase System B #1: whole-blob interception injected into dart_snapshot.cc")
