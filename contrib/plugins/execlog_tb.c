/*
 * Copyright (C) 2021-2024, Alexandre Iooss <erdnaxe@crans.org>
 *
 * Log TB execution
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include <stdio.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* Log last instruction without checking regs, setup next */
static void vcpu_insn_exec(unsigned int cpu_index, void *udata)
{
    //fprintf(stderr, "0x%"PRIx64"\n", (uint64_t)udata);

    char rawaddr[] = {
        ((uint64_t)udata >> 0) & 0xFF,
        ((uint64_t)udata >> 8) & 0xFF,
        ((uint64_t)udata >> 16) & 0xFF,
        ((uint64_t)udata >> 24) & 0xFF,
        ((uint64_t)udata >> 32) & 0xFF,
        ((uint64_t)udata >> 40) & 0xFF,
        ((uint64_t)udata >> 48) & 0xFF,
        ((uint64_t)udata >> 56) & 0xFF
    };
    fwrite(rawaddr, 1, 8, stderr);
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
    /* Register translation block callback */
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);

    return 0;
}
