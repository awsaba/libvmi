/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
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
#include "driver/interface.h"
#include "arch/arch_interface.h"
#include <stdlib.h>
#include <sys/mman.h>

GSList* vmi_get_va_pages(vmi_instance_t vmi, addr_t dtb) {
    if(vmi->arch_interface->get_va_pages) {
        return vmi->arch_interface->get_va_pages(vmi, dtb);
    } else {
        errprint("Invalid or not supported paging mode during get_va_pages\n");
        return NULL;
    }
}

addr_t vmi_pagetable_lookup (vmi_instance_t vmi, addr_t dtb, addr_t vaddr)
{

    page_info_t info = {0};

    /* check if entry exists in the cachec */
    if (VMI_SUCCESS == v2p_cache_get(vmi, vaddr, dtb, &info.paddr)) {

        /* verify that address is still valid */
        uint8_t value = 0;

        if (VMI_SUCCESS == vmi_read_8_pa(vmi, info.paddr, &value)) {
            return info.paddr;
        }
        else {
            v2p_cache_del(vmi, vaddr, dtb);
        }
    }

    if(vmi->arch_interface->v2p) {
        vmi->arch_interface->v2p(vmi, dtb, vaddr, &info);
    } else {
        errprint("Invalid paging mode during vmi_pagetable_lookup\n");
    }

    /* add this to the cache */
    if (info.paddr) {
        v2p_cache_set(vmi, vaddr, dtb, info.paddr);
    }
    return info.paddr;
}

status_t vmi_pagetable_lookup_extended(
    vmi_instance_t vmi,
    addr_t dtb,
    addr_t vaddr,
    page_info_t *info)
{
    status_t ret = VMI_FAILURE;

    if(!info) return ret;

    memset(info, 0, sizeof(page_info_t));
    info->vaddr = vaddr;
    info->dtb = dtb;

    if(vmi->arch_interface->v2p) {
        vmi->arch_interface->v2p(vmi, dtb, vaddr, info);
    } else {
        errprint("Invalid paging mode during vmi_pagetable_lookup\n");
    }

    if(info->paddr) {
        ret = VMI_SUCCESS;
    }

    return ret;
}

/* expose virtual to physical mapping for kernel space via api call */
addr_t vmi_translate_kv2p (vmi_instance_t vmi, addr_t virt_address)
{
    reg_t cr3 = 0;

    if (vmi->kpgd) {
        cr3 = vmi->kpgd;
    }
    else {
        driver_get_vcpureg(vmi, &cr3, CR3, 0);
    }
    if (!cr3) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--early bail on v2p lookup because cr3 is zero\n");
        return 0;
    }
    else {
        return vmi_pagetable_lookup(vmi, cr3, virt_address);
    }
}

/* expose virtual to physical mapping for user space via api call */
addr_t vmi_translate_uv2p_nocache (vmi_instance_t vmi, addr_t virt_address,
        vmi_pid_t pid)
{
    addr_t dtb = vmi_pid_to_dtb(vmi, pid);

    if (!dtb) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--early bail on v2p lookup because dtb is zero\n");
        return 0;
    }
    else {
        addr_t rtnval = vmi_pagetable_lookup(vmi, dtb, virt_address);

        if (!rtnval) {
            pid_cache_del(vmi, pid);
        }
        return rtnval;
    }
}

addr_t vmi_translate_uv2p (vmi_instance_t vmi, addr_t virt_address, vmi_pid_t pid)
{
    addr_t dtb = vmi_pid_to_dtb(vmi, pid);

    if (!dtb) {
        dbprint(VMI_DEBUG_PTLOOKUP, "--early bail on v2p lookup because dtb is zero\n");
        return 0;
    }
    else {
        addr_t rtnval = vmi_pagetable_lookup(vmi, dtb, virt_address);

        if (!rtnval) {
            if (VMI_SUCCESS == pid_cache_del(vmi, pid)) {
                return vmi_translate_uv2p_nocache(vmi, virt_address, pid);
            }
        }
        return rtnval;
    }
}
