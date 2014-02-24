/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "libvmi.h"
#include "private.h"
#include "arch_interface.h"
#include "intel.h"
#include "amd64.h"
#include <stdlib.h>

/*
 * check that this vm uses a paging method that we support
 * and set pm/cr3/pae/pse/lme flags optionally on the given pointers
 */
status_t get_memory_layout(vmi_instance_t vmi) {
    // To get the paging layout, the following bits are needed:
    // 1. CR0.PG
    // 2. CR4.PAE
    // 3. Either (a) IA32_EFER.LME, or (b) the guest's address width (32 or
    //    64). Not all backends allow us to read an MSR; in particular, Xen's PV
    //    backend doessn't.

    status_t ret = VMI_FAILURE;
    page_mode_t pm = VMI_PM_UNKNOWN;
    uint8_t dom_addr_width = 0; // domain address width (bytes)

    /* pull info from registers, if we can */
    reg_t cr0, cr3, cr4, efer;
    int pae = 0, pse = 0, lme = 0;
    uint8_t msr_efer_lme = 0;   // LME bit in MSR_EFER

    /* skip all of this for files */
    if (VMI_FILE == vmi->mode) {
        goto _exit;
    }
    /* get the control register values */
    if (driver_get_vcpureg(vmi, &cr0, CR0, 0) == VMI_FAILURE) {
        errprint("**failed to get CR0\n");
        goto _exit;
    }

    /* PG Flag --> CR0, bit 31 == 1 --> paging enabled */
    if (!VMI_GET_BIT(cr0, 31)) {
        errprint("Paging disabled for this VM, not supported.\n");
        goto _exit;
    }

    //
    // Paging enabled (PG==1)
    //
    if (driver_get_vcpureg(vmi, &cr4, CR4, 0) == VMI_FAILURE) {
        errprint("**failed to get CR4\n");
        goto _exit;
    }

    /* PSE Flag --> CR4, bit 5 */
    pae = VMI_GET_BIT(cr4, 5);
    dbprint(VMI_DEBUG_CORE, "**set pae = %d\n", pae);

    /* PSE Flag --> CR4, bit 4 */
    pse = VMI_GET_BIT(cr4, 4);
    dbprint(VMI_DEBUG_CORE, "**set pse = %d\n", pse);

    ret = driver_get_vcpureg(vmi, &efer, MSR_EFER, 0);
    if (VMI_SUCCESS == ret) {
        lme = VMI_GET_BIT(efer, 8);
        dbprint(VMI_DEBUG_CORE, "**set lme = %d\n", lme);
    }
    else {
        dbprint(VMI_DEBUG_CORE, "**failed to get MSR_EFER, trying method #2\n");

        // does this trick work in all cases?
        ret = driver_get_address_width(vmi, &dom_addr_width);
        if (VMI_FAILURE == ret) {
            errprint
                ("Failed to get domain address width. Giving up.\n");
            goto _exit;
        }
        lme = (8 == dom_addr_width);
        dbprint
            (VMI_DEBUG_CORE, "**found guest address width is %d bytes; assuming IA32_EFER.LME = %d\n",
             dom_addr_width, lme);
    }   // if
    // Get current cr3 for sanity checking
    if (driver_get_vcpureg(vmi, &cr3, CR3, 0) == VMI_FAILURE) {
        errprint("**failed to get CR3\n");
        goto _exit;
    }

    // now determine addressing mode
    if (0 == pae) {
        dbprint(VMI_DEBUG_CORE, "**32-bit paging\n");
        pm = VMI_PM_LEGACY;
        cr3 &= 0xFFFFF000ull;
    }
    // PAE == 1; determine IA-32e or PAE
    else if (lme) {    // PAE == 1, LME == 1
        dbprint(VMI_DEBUG_CORE, "**IA-32e paging\n");
        pm = VMI_PM_IA32E;
        cr3 &= 0xFFFFFFFFFFFFF000ull;
    }
    else {  // PAE == 1, LME == 0
        dbprint(VMI_DEBUG_CORE, "**PAE paging\n");
        pm = VMI_PM_PAE;
        cr3 &= 0xFFFFFFE0;
    }   // if-else
    dbprint(VMI_DEBUG_CORE, "**sanity checking cr3 = 0x%.16"PRIx64"\n", cr3);

    /* testing to see CR3 value */
    if (!driver_is_pv(vmi) && cr3 > vmi->size) {   // sanity check on CR3
        dbprint(VMI_DEBUG_CORE, "** Note cr3 value [0x%"PRIx64"] exceeds memsize [0x%"PRIx64"]\n",
                cr3, vmi->size);
    }

    vmi->page_mode = pm;
    vmi->pae = pae;
    vmi->pse = pse;
    vmi->lme = lme;

_exit:
    return ret;
}

status_t arch_init(vmi_instance_t vmi) {

    status_t ret = VMI_FAILURE;

    if (vmi->arch_interface != NULL) {
        errprint("VMI_ERROR: arch interface already initialized\n");
        return ret;
    }

    if(VMI_FAILURE == get_memory_layout(vmi)) {
        return ret;
    }

    if (vmi->page_mode == VMI_PM_LEGACY || vmi->page_mode == VMI_PM_PAE) {
        ret = intel_init(vmi);
    } else if (vmi->page_mode == VMI_PM_IA32E) {
        ret = amd64_init(vmi);
    }

    return ret;
}
