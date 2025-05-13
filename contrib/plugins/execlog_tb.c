/*
 * Copyright (C) 2025, Ambre Iooss <aiooss@crans.org>
 *
 * Log translated blocks executions.
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include <stdio.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static FILE *output_file;

/* Log last instruction without checking regs, setup next */
static void vcpu_insn_exec(unsigned int cpu_index, void *udata)
{
    uint64_t insn_vaddr = (uint64_t)udata;
    char *msg;

    if (output_file) {
        char rawdata[] = {
            cpu_index,
            (insn_vaddr >> 0) & 0xFF,
            (insn_vaddr >> 8) & 0xFF,
            (insn_vaddr >> 16) & 0xFF,
            (insn_vaddr >> 24) & 0xFF,
            (insn_vaddr >> 32) & 0xFF,
            (insn_vaddr >> 40) & 0xFF,
            (insn_vaddr >> 48) & 0xFF,
            (insn_vaddr >> 56) & 0xFF
        };
        fwrite(rawdata, 1, 9, output_file);
    } else {
        msg = g_strdup_printf("cpu=%d, tb=0x%"PRIx64"\n", cpu_index, insn_vaddr);
        qemu_plugin_outs(msg);
    }
}

/**
 * On translation block new translation
 *
 * QEMU convert code by translation block (TB). By hooking here we can then hook
 * a callback on the first instruction of the block.
 */
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    struct qemu_plugin_insn *insn;

    // TODO
    //size_t n_insns = qemu_plugin_tb_n_insns(tb);
    /* Log memory addr of first instruction of TB */
    insn = qemu_plugin_tb_get_insn(tb, 0);
    uint64_t insn_vaddr = qemu_plugin_insn_vaddr(insn);
    qemu_plugin_register_vcpu_insn_exec_cb(
        insn, vcpu_insn_exec,
        QEMU_PLUGIN_CB_NO_REGS,
        (void*)insn_vaddr);
}

/**
 * Install the plugin
 */
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
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

    /* Register translation block callback */
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);

    return 0;
}
