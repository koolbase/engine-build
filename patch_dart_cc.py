#!/usr/bin/env python3

target_path = "engine/src/flutter/runtime/dart_isolate.cc"

with open(target_path, 'r') as f:
    content = f.read()

# Add includes
include_marker = '#include "third_party/tonic/scopes/dart_isolate_scope.h"'
include_addition = include_marker + '''
#include <cstdio>
#include <cstdarg>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/mman.h>'''
content = content.replace(include_marker, include_addition, 1)

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

static bool Koolbase_FetchPatch(uint8_t* buf, size_t buf_len) {
  const char* host = "127.0.0.1";
  const char* port_str = "9876";

  struct addrinfo hints = {};
  struct addrinfo* res = nullptr;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(host, port_str, &hints, &res) != 0) {
    kb_log("DNS failed");
    return false;
  }

  int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sock < 0) {
    freeaddrinfo(res);
    kb_log("socket failed");
    return false;
  }

  if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
    freeaddrinfo(res);
    close(sock);
    kb_log("connect failed");
    return false;
  }
  freeaddrinfo(res);

  const char* request = "GET /patch HTTP/1.0\\r\\nHost: 127.0.0.1:9876\\r\\nConnection: close\\r\\n\\r\\n";
  send(sock, request, strlen(request), 0);

  char response[2048] = {};
  int total = 0;
  int n;
  while ((n = recv(sock, response + total, sizeof(response) - total - 1, 0)) > 0) {
    total += n;
  }
  close(sock);

  const char* header_end = strstr(response, "\\r\\n\\r\\n");
  if (header_end == nullptr) {
    kb_log("bad HTTP response");
    return false;
  }

  const uint8_t* body = reinterpret_cast<const uint8_t*>(header_end + 4);
  size_t body_len = total - (header_end + 4 - response);

  if (body_len < buf_len) {
    kb_log("response too short: %zu bytes", body_len);
    return false;
  }

  memcpy(buf, body, buf_len);
  kb_log("fetched %zu bytes", buf_len);
  return true;
}

static bool Koolbase_FindAndPatchMarker(const uint8_t* snapshot_data,
                                        size_t scan_size,
                                        const char* new_price) {
  const char* marker = "KBPRICE@@@";
  size_t marker_len = 10;

  kb_log("scanning %zu bytes from %p", scan_size, snapshot_data);

  for (size_t i = 0; i < scan_size - marker_len - 3; i++) {
    bool match = true;
    for (size_t j = 0; j < marker_len; j++) {
      if (snapshot_data[i+j] != marker[j]) {
        match = false;
        break;
      }
    }
    if (match) {
      uint8_t* target = (uint8_t*)(snapshot_data + i + 10);
      kb_log("found marker at offset 0x%lx target %p", (unsigned long)i, target);

      long page_size = sysconf(_SC_PAGESIZE);
      uintptr_t page_start = (uintptr_t)target & ~(page_size - 1);
      uintptr_t target_end = (uintptr_t)target + 3;
      size_t protect_len = ((target_end - page_start + page_size - 1) / page_size) * page_size;
      kb_log("page_size=%ld page_start=0x%lx protect_len=%zu", page_size, page_start, protect_len);

      if (mprotect((void*)page_start, protect_len, PROT_READ | PROT_WRITE) != 0) {
        kb_log("mprotect RW failed errno=%d", errno);
        return false;
      }

      target[0] = new_price[0];
      target[1] = new_price[1];
      target[2] = new_price[2];

      if (mprotect((void*)page_start, protect_len, PROT_READ) != 0) {
        kb_log("mprotect R failed errno=%d", errno);
      }

      kb_log("patched marker with new price: %c%c%c", new_price[0], new_price[1], new_price[2]);
      return true;
    }
  }
  kb_log("marker not found in scan");
  return false;
}

namespace flutter {'''

content = content.replace('namespace flutter {', koolbase_code, 1)

target_marker = '''  phase_ = Phase::Ready;
  return true;
}

bool DartIsolate::LoadKernel('''

replacement = '''  phase_ = Phase::Ready;

  // ==== KOOLBASE PATCH HOOK ====
  { FILE* f = fopen("/tmp/koolbase_log.txt", "w"); if (f) fclose(f); }
  kb_log("hook entered at PrepareForRunningFromPrecompiledCode");

  uint8_t patch_buf[128];
  if (Koolbase_FetchPatch(patch_buf, 128)) {
    kb_log("fetch returned true, magic bytes: %c%c%c%c",
           patch_buf[0], patch_buf[1], patch_buf[2], patch_buf[3]);

    if (patch_buf[0]=='K'&&patch_buf[1]=='B'&&patch_buf[2]=='P'&&patch_buf[3]=='M') {
      char new_price[4] = {0};
      new_price[0] = patch_buf[40];
      new_price[1] = patch_buf[41];
      new_price[2] = patch_buf[42];
      kb_log("new price from patch: %s", new_price);

      auto snapshot = GetIsolateGroupData().GetIsolateSnapshot();
      auto data_mapping = snapshot->GetDataMapping();
      const uint8_t* snapshot_data = data_mapping;
      kb_log("snapshot data at %p", snapshot_data);

      Koolbase_FindAndPatchMarker(snapshot_data, 16 * 1024 * 1024, new_price);
    } else {
      kb_log("invalid magic number");
    }
  } else {
    kb_log("fetch returned false");
  }
  // ==== END KOOLBASE ====

  return true;
}

bool DartIsolate::LoadKernel('''

if target_marker not in content:
    print("ERROR: Could not find insertion point")
    exit(1)

content = content.replace(target_marker, replacement, 1)

with open(target_path, 'w') as f:
    f.write(content)

print("Koolbase Phase 2c-v3 (page-size fix) applied")
