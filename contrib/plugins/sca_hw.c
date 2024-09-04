/*
 * Copyright (C) 2024, Alexandre Iooss <erdnaxe@crans.org>
 *
 * Simulate side-channel leakage using a Hamming weight mode on written
 * registers.
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include <glib.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <qemu-plugin.h>

typedef struct {
  struct qemu_plugin_register *handle;
  GByteArray *last;
  GByteArray *new;
} Register;

typedef struct CPU {
  int last_cpu_index;
  /* Ptr array of Register */
  GPtrArray *registers;
} CPU;

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static GArray *cpus;
static GRWLock expand_array_lock;

static const char HAMMING_WEIGHT[] = {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4,
    2, 3, 3, 4, 3, 4, 4, 5, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 1, 2, 2, 3, 2, 3, 3, 4,
    2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6,
    4, 5, 5, 6, 5, 6, 6, 7, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5,
    3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6,
    4, 5, 5, 6, 5, 6, 6, 7, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8};

static CPU *get_cpu(int vcpu_index) {
  CPU *c;
  g_rw_lock_reader_lock(&expand_array_lock);
  c = &g_array_index(cpus, CPU, vcpu_index);
  g_rw_lock_reader_unlock(&expand_array_lock);

  return c;
}

/**
 * Log instruction execution, outputting the last one.
 */
static uint64_t compute_hw_reg_leakage(CPU *cpu) {
  uint64_t leakage = 0;
  for (int n = 0; n < cpu->registers->len; n++) {
    Register *reg = cpu->registers->pdata[n];
    int sz;

    g_byte_array_set_size(reg->new, 0);
    sz = qemu_plugin_read_register(reg->handle, reg->new);
    g_assert(sz == reg->last->len);

    if (memcmp(reg->last->data, reg->new->data, sz)) {
      GByteArray *temp = reg->last;
      for (int i = sz - 1; i >= 0; i--) {
        leakage += HAMMING_WEIGHT[reg->new->data[i]];
      }
      reg->last = reg->new;
      reg->new = temp;
    }
  }
  return leakage;
}

/* Log last instruction while checking registers */
static void vcpu_insn_exec(unsigned int cpu_index, void *udata) {
  CPU *cpu = get_cpu(cpu_index);
  char *msg;
  uint64_t leakage = 0;

  /* Log previous instruction leakage */
  if (cpu->last_cpu_index != -1) {
    leakage = compute_hw_reg_leakage(cpu);
    msg = g_strdup_printf("cpu=%d, hw_leakage=%ld\n", cpu->last_cpu_index,
                          leakage);
    qemu_plugin_outs(msg);
  }

  cpu->last_cpu_index = cpu_index;
}

/**
 * On translation block new translation
 *
 * QEMU convert code by translation block (TB). By hooking here we can then hook
 * a callback on each instruction.
 */
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
  struct qemu_plugin_insn *insn;

  size_t n_insns = qemu_plugin_tb_n_insns(tb);
  for (size_t i = 0; i < n_insns; i++) {
    /* Register callback on instruction */
    insn = qemu_plugin_tb_get_insn(tb, i);
    qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                           QEMU_PLUGIN_CB_R_REGS, NULL);
  }
}

static Register *init_vcpu_register(qemu_plugin_reg_descriptor *desc) {
  Register *reg = g_new0(Register, 1);
  int r;

  reg->handle = desc->handle;
  reg->last = g_byte_array_new();
  reg->new = g_byte_array_new();

  /* read the initial value */
  r = qemu_plugin_read_register(reg->handle, reg->last);
  g_assert(r > 0);
  return reg;
}

static GPtrArray *registers_init(int vcpu_index) {
  g_autoptr(GPtrArray) registers = g_ptr_array_new();
  g_autoptr(GArray) reg_list = qemu_plugin_get_registers();

  /* Track all registers */
  for (int r = 0; r < reg_list->len; r++) {
    qemu_plugin_reg_descriptor *rd =
        &g_array_index(reg_list, qemu_plugin_reg_descriptor, r);
    Register *reg = init_vcpu_register(rd);
    g_ptr_array_add(registers, reg);
  }

  return registers->len ? g_steal_pointer(&registers) : NULL;
}

/*
 * Initialise a new vcpu/thread with:
 *   - last_cpu_index tracking data
 *   - list of tracked registers
 *   - initial value of registers
 *
 * As we could have multiple threads trying to do this we need to
 * serialise the expansion under a lock.
 */
static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index) {
  CPU *c;

  g_rw_lock_writer_lock(&expand_array_lock);
  if (vcpu_index >= cpus->len) {
    g_array_set_size(cpus, vcpu_index + 1);
  }
  g_rw_lock_writer_unlock(&expand_array_lock);

  c = get_cpu(vcpu_index);
  c->last_cpu_index = -1;
  c->registers = registers_init(vcpu_index);
}

/**
 * Install the plugin
 */
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv) {
  /*
   * Initialize dynamic array to cache vCPU instruction. In user mode
   * we don't know the size before emulation.
   */
  cpus = g_array_sized_new(true, true, sizeof(CPU),
                           info->system_emulation ? info->system.max_vcpus : 1);

  /* Register init and translation block callbacks */
  qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
  qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);

  return 0;
}
