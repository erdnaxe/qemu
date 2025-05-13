/*
 * Copyright (C) 2025, Ambre Iooss <aiooss@crans.org>
 *
 * Simulate side-channel leakage using a Hamming weight mode on written
 * registers.
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include <stdio.h>

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
static FILE *output_file;

static CPU *get_cpu(int vcpu_index) {
    CPU *c;
    g_rw_lock_reader_lock(&expand_array_lock);
    c = &g_array_index(cpus, CPU, vcpu_index);
    g_rw_lock_reader_unlock(&expand_array_lock);

    return c;
}

#if defined(__GNUC__) || defined(__clang__)
static inline unsigned char cpopcount(unsigned char x) {
    return __builtin_popcountll(x);
}
#elif defined(_MSC_VER) && defined(_WIN64)
#include <intrin.h>
static inline unsigned char cpopcount(unsigned char x) {
    return __popcnt(x);
}
#else
#error "unsupported compiler"
#endif

/**
 * Log instruction execution, outputting the last one.
 */
static uint8_t compute_hw_reg_leakage(CPU *cpu)
{
    uint8_t leakage = 0;
    for (int n = 0; n < cpu->registers->len; n++) {
        Register *reg = cpu->registers->pdata[n];
        int sz;

        g_byte_array_set_size(reg->new, 0);
        sz = qemu_plugin_read_register(reg->handle, reg->new);
        g_assert(sz == reg->last->len);

        if (memcmp(reg->last->data, reg->new->data, sz)) {
            GByteArray *temp = reg->last;
            for (int i = sz - 1; i >= 0; i--) {
                leakage += cpopcount(reg->new->data[i]);
            }
            reg->last = reg->new;
            reg->new = temp;
        }
    }
    return leakage;
}

/* Log last instruction while checking registers */
static void vcpu_insn_exec(unsigned int cpu_index, void *udata)
{
    CPU *cpu = get_cpu(cpu_index);
    char *msg;
    uint8_t leakage = 0;
    uint8_t rawdata[2];

    /* Log previous instruction leakage */
    if (cpu->last_cpu_index != -1) {
        leakage = compute_hw_reg_leakage(cpu);
        if (output_file) {
            rawdata[0] = cpu->last_cpu_index;
            rawdata[1] = leakage;
            fwrite(rawdata, 1, 2, output_file);
        } else {
            msg = g_strdup_printf("cpu=%d, leakage=%d\n", cpu->last_cpu_index,
                leakage);
            qemu_plugin_outs(msg);
        }
    }

    cpu->last_cpu_index = cpu_index;
}

/**
 * On translation block new translation
 *
 * QEMU convert code by translation block (TB). By hooking here we can then hook
 * a callback on each instruction.
 */
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    struct qemu_plugin_insn *insn;

    size_t n_insns = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n_insns; i++) {
        /* Register callback on instruction */
        insn = qemu_plugin_tb_get_insn(tb, i);
        qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, vcpu_insn_exec,
                    QEMU_PLUGIN_CB_R_REGS,
                    NULL);
    }
}

static Register *init_vcpu_register(qemu_plugin_reg_descriptor *desc)
{
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

static GPtrArray *registers_init(int vcpu_index)
{
    g_autoptr(GPtrArray) registers = g_ptr_array_new();
    g_autoptr(GArray) reg_list = qemu_plugin_get_registers();

    /* Track all registers */
    for (int r = 0; r < reg_list->len; r++) {
        qemu_plugin_reg_descriptor *rd = &g_array_index(
            reg_list, qemu_plugin_reg_descriptor, r);
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
static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
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
                                           char **argv)
{
    /*
     * Initialize dynamic array to cache vCPU instruction. In user mode
     * we don't know the size before emulation.
     */
     cpus = g_array_sized_new(true, true, sizeof(CPU),
     info->system_emulation ? info->system.max_vcpus : 1);

    /* Parse output filename */
    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
        if (g_strcmp0(tokens[0], "output") == 0) {
            output_file = fopen(tokens[1], "wb");
            if (!output_file) {
                fprintf(stderr, "failed to open output file: %s\n", tokens[1]);
                return -1;
            }
        } else {
            fprintf(stderr, "option parsing failed: %s\n", opt);
            return -1;
        }
    }

    /* Register init and translation block callbacks */
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);

    return 0;
}
