#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

#define MAX_DATA_SIZE 1024 * 4


/***********************************************************
 * https://n-2.org/
 * Network Security Services (NSS)
 * https://firefox-source-docs.mozilla.org/security/nss/index.html
 ***********************************************************/

// Optional Target PID
const volatile u64 target_pid = 0;

enum ssl_data_event_type { kSSLRead, kSSLWrite };

struct ssl_data_event_t {
  enum ssl_data_event_type type;
  uint64_t timestamp_ns;
  uint32_t pid;
  uint32_t tid;
  char data[MAX_DATA_SIZE];
  int32_t data_len;
  char comm[TASK_COMM_LEN];
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} gnutls_events SEC(".maps");

/***********************************************************
 * Internal structs and definitions
 ***********************************************************/

// Key is thread ID (from bpf_get_current_pid_tgid).
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, const char*);
    __uint(max_entries, 1024);
} active_ssl_read_args_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, const char*);
    __uint(max_entries, 1024);
} active_ssl_write_args_map SEC(".maps");

// BPF programs are limited to a 512-byte stack. We store this value per CPU
// and use it as a heap allocated value.
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct ssl_data_event_t);
    __uint(max_entries, 1);
} data_buffer_heap SEC(".maps");

/***********************************************************
 * General helper functions
 ***********************************************************/

static __inline struct ssl_data_event_t* create_ssl_data_event(uint64_t current_pid_tgid) {
  uint32_t kZero = 0;
  struct ssl_data_event_t* event = bpf_map_lookup_elem(&data_buffer_heap, &kZero);
  if (event == NULL) {
    return NULL;
  }

  const uint32_t kMask32b = 0xffffffff;
  event->timestamp_ns = bpf_ktime_get_ns();
  event->pid = current_pid_tgid >> 32;
  event->tid = current_pid_tgid & kMask32b;

  return event;
}

/***********************************************************
 * BPF syscall processing functions
 ***********************************************************/

static int process_SSL_data(struct pt_regs* ctx, uint64_t id, enum ssl_data_event_type type,
                            const char* buf) {
  int len = (int)(ctx)->ax;
  if (len < 0) {
    return 0;
  }

  struct ssl_data_event_t* event = create_ssl_data_event(id);
  if (event == NULL) {
    return 0;
  }

  event->type = type;
  // This is a max function, but it is written in such a way to keep older BPF verifiers happy.
  event->data_len = (len < MAX_DATA_SIZE ? (len & (MAX_DATA_SIZE - 1)) : MAX_DATA_SIZE);
  bpf_probe_read(event->data, event->data_len, buf);
  bpf_get_current_comm(&event->comm, sizeof(event->comm));
  bpf_perf_event_output(ctx, &gnutls_events, BPF_F_CURRENT_CPU, event,sizeof(struct ssl_data_event_t));
  return 0;
}

/***********************************************************
 * BPF probe function entry-points
 ***********************************************************/

// http://gnu.ist.utl.pt/software/gnutls/manual/gnutls/gnutls.html#gnutls_record_send
// Function signature being probed:
// ssize_t gnutls_record_send (gnutls_session session, const void * data, size_t sizeofdata)

SEC("uprobe/gnutls_record_send")
int probe_entry_SSL_write(struct pt_regs* ctx) {
  uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
  uint32_t pid = current_pid_tgid >> 32;

    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }

  const char* buf = (const char*)(ctx)->si;
  bpf_map_update_elem(&active_ssl_write_args_map, &current_pid_tgid, &buf, BPF_ANY);
  return 0;
}

SEC("uretprobe/gnutls_record_send")
int probe_ret_SSL_write(struct pt_regs* ctx) {
  uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
  uint32_t pid = current_pid_tgid >> 32;

    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }

  const char** buf = bpf_map_lookup_elem(&active_ssl_write_args_map, &current_pid_tgid);
  if (buf != NULL) {
    process_SSL_data(ctx, current_pid_tgid, kSSLWrite, *buf);
  }

  bpf_map_delete_elem(&active_ssl_write_args_map, &current_pid_tgid);
  return 0;
}

// Function signature being probed:
// int SSL_read(SSL *s, void *buf, int num)
// ssize_t gnutls_record_recv (gnutls_session session, void * data, size_t sizeofdata)

SEC("uprobe/gnutls_record_recv")
int probe_entry_SSL_read(struct pt_regs* ctx) {
  uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
  uint32_t pid = current_pid_tgid >> 32;

    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }

  const char* buf = (const char*)(ctx)->si;
  bpf_map_update_elem(&active_ssl_read_args_map, &current_pid_tgid, &buf, BPF_ANY);
  return 0;
}

SEC("uretprobe/gnutls_record_recv")
int probe_ret_SSL_read(struct pt_regs* ctx) {
  uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
  uint32_t pid = current_pid_tgid >> 32;

    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }

  const char** buf = bpf_map_lookup_elem(&active_ssl_read_args_map, &current_pid_tgid);
  if (buf != NULL) {
    process_SSL_data(ctx, current_pid_tgid, kSSLRead, *buf);
  }

  bpf_map_delete_elem(&active_ssl_read_args_map, &current_pid_tgid);

  return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
