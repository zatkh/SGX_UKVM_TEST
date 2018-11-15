#include <os>
#include <kprint>
#include <kernel/memory.hpp>
#include <util/crc32.hpp>
using namespace util::literals;

#define SOFT_RESET_MAGIC    0xFEE1DEAD
#define SOFT_RESET_LOCATION 0x8200

namespace x86 {
  extern uint32_t apic_timer_get_ticks() noexcept;
  extern void     apic_timer_set_ticks(uint32_t) noexcept;
}
extern char _end;

struct softreset_t
{
  uint32_t  checksum;
  uint64_t  liveupdate_loc;
  uint64_t  high_mem;
  KHz       cpu_freq;
  uint32_t  apic_ticks;
  uint64_t  extra;
  uint32_t  extra_len;
};

bool OS::is_softreset_magic(uint32_t value)
{
  return value == SOFT_RESET_MAGIC;
}

__attribute__((weak))
void softreset_service_handler(const void*, size_t) {}

uintptr_t OS::softreset_memory_end(intptr_t addr)
{
  auto* data = (softreset_t*) addr;
  assert(data->high_mem > (uintptr_t) &_end);
  //kprintf("Restored memory end: %p\n", data->high_mem);
  return data->high_mem;
}

void OS::resume_softreset(intptr_t addr)
{
  auto* data = (softreset_t*) addr;

  /// validate soft-reset data
  const uint32_t csum_copy = data->checksum;
  data->checksum = 0;
  uint32_t crc = crc32_fast(data, sizeof(softreset_t));
  if (crc != csum_copy) {
    kprintf("[!] Failed to verify CRC of softreset data: %08x vs %08x\n",
            crc, csum_copy);
    return;
  }
  data->checksum = csum_copy;

  /// restore known values
  uintptr_t lu_phys = data->liveupdate_loc;
  OS::setup_liveupdate(lu_phys);
  OS::memory_end_     = data->high_mem;
  OS::heap_max_       = OS::memory_end_ - 1;
  OS::cpu_khz_        = data->cpu_freq;
  x86::apic_timer_set_ticks(data->apic_ticks);
  OS::m_is_live_updated = true;

  /// call service-specific softreset handler
  softreset_service_handler((void*) data->extra, data->extra_len);
}

extern "C"
void* __os_store_soft_reset(void* extra, size_t extra_len)
{
  // store softreset data in low memory
  auto* data = (softreset_t*) SOFT_RESET_LOCATION;
  data->checksum    = 0;
  data->liveupdate_loc = os::mem::virt_to_phys((uintptr_t) OS::liveupdate_storage_area());
  data->high_mem    = OS::memory_end();
  data->cpu_freq    = OS::cpu_freq();
  data->apic_ticks  = x86::apic_timer_get_ticks();
  data->extra       = (uint64_t) extra;
  data->extra_len   = extra_len;

  uint32_t csum = crc32_fast(data, sizeof(softreset_t));
  data->checksum = csum;
  return data;
}
