#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PIN_GLOBAL_NS 2
#define TASK_COMM_LEN 16

struct kprobe_event {
  __u64 tstamp;
  __u64 pid;
  __u32 pad;
  __u32 cpu_id;
  char comm[TASK_COMM_LEN];
  char filename[255];
} __attribute__((aligned(8)));

struct bpf_map_def_pvt {
  __u32 type;
  __u32 key_size;
  __u32 value_size;
  __u32 max_entries;
  __u32 map_flags;
  __u32 pinning;
  __u32 inner_map_fd;
};

struct bpf_map_def_pvt SEC("maps") event = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 256 * 1024,
    .pinning = PIN_GLOBAL_NS,
};

SEC("kprobe/do_unlinkat")
int handle_kprobe(struct pt_regs *ctx) {
  struct kprobe_event ev = {0};
  struct filename *name;
  const char *filename;

  ev.pid = bpf_get_current_pid_tgid() >> 32;
  ev.tstamp = bpf_ktime_get_ns();
  ev.cpu_id = bpf_get_smp_processor_id();
  bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
  name = (struct filename *)PT_REGS_PARM2(ctx);
  filename = BPF_CORE_READ(name, name);
  bpf_probe_read(&ev.filename, sizeof(ev.filename), filename);

  bpf_ringbuf_output(&event, &ev, sizeof(ev), 2);

  return 0;
}

char __license[] SEC("license") = "GPL";
