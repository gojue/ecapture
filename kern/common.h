#ifndef BAD_BPF_COMMON_H
#define BAD_BPF_COMMON_H

#define MAX_PAYLOAD_LEN 150


// These are used by a number of
// different programs to sync eBPF Tail Call
// login between user space and kernel
#define PROG_00 0
#define PROG_01 1
#define PROG_02 2

// Used when replacing text
#define FILENAME_LEN_MAX 50
#define TEXT_LEN_MAX 20

// Simple message structure to get events from eBPF Programs
// in the kernel to user spcae
#define TASK_COMM_LEN 16
struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    bool success;
};

#pragma once

#define MAX_DATA_SIZE 4096

enum ssl_data_event_type { kSSLRead, kSSLWrite };

struct ssl_data_event_t {
  enum ssl_data_event_type type;
  uint64_t timestamp_ns;
  uint32_t pid;
  uint32_t tid;
  char data[MAX_DATA_SIZE];
  int32_t data_len;
};