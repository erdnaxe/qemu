/*
 * Copyright (C) 2024, Simon Hamelin <simon.hamelin@grenoble-inp.org>
 *
 * Skip an instruction at the given address.
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static uint64_t icount;
static uint64_t executed_instructions;

static GHashTable *insn_ht;
static GMutex hashtable_lock;

typedef struct {
    uint64_t vaddr;
    size_t size;
} InsnInfo;

static void vcpu_insn_exec(unsigned int cpu_index, void *udata)
{
    InsnInfo *insn_info = udata;

    if (executed_instructions == icount) {
        executed_instructions++;
        char *msg = g_strdup_printf(
            "skipping instruction at address 0x%" PRIx64 "\n",
            insn_info->vaddr);
        qemu_plugin_outs(msg);
        qemu_plugin_set_pc(insn_info->vaddr + insn_info->size);
        msg = g_strdup_printf("pc has been set to 0x%" PRIx64 "\n",
                                insn_info->vaddr + insn_info->size);
        qemu_plugin_outs(msg);
        qemu_plugin_exit_current_tb();
    }

    executed_instructions++;
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t tb_n = qemu_plugin_tb_n_insns(tb);
    InsnInfo *info;

    for (size_t i = 0; i < tb_n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t insn_vaddr = qemu_plugin_insn_vaddr(insn);

        g_mutex_lock(&hashtable_lock);
        info = g_hash_table_lookup(insn_ht, GUINT_TO_POINTER(insn_vaddr));
        if (info == NULL) {
            info = g_new0(InsnInfo, 1);
            info->vaddr = insn_vaddr;
            info->size = qemu_plugin_insn_size(insn);
            g_hash_table_insert(insn_ht, GUINT_TO_POINTER(insn_vaddr),
                                (gpointer)info);
        }
        g_mutex_unlock(&hashtable_lock);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                               QEMU_PLUGIN_CB_NO_REGS, info);
    }
}

static void free_insn_info(gpointer data)
{
    InsnInfo *insn_info = data;
    g_free(insn_info);
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    g_hash_table_destroy(insn_ht);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
    bool icount_set = false;

    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
        if (g_strcmp0(tokens[0], "icount") == 0) {
            icount_set = true;
            icount = g_ascii_strtoull(tokens[1], NULL, 10);
        } else {
            fprintf(stderr, "option parsing failed: %s\n", opt);
            return -1;
        }
    }

    if (!icount_set) {
        fprintf(stderr, "'icount' should be specified");
        return -1;
    }

    insn_ht = g_hash_table_new_full(NULL, g_direct_equal, NULL, free_insn_info);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    return 0;
}
