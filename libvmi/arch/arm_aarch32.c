/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Tamas K Lengyel (tklengyel@sec.in.tum.de)
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

#include <glib.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "private.h"
#include "driver/driver_wrapper.h"
#include "arch/arm_aarch32.h"

static inline
uint32_t first_level_table_index(uint32_t vaddr) {
    return (vaddr >> 20);
}

// 1st Level Descriptor
static inline
void get_first_level_descriptor(vmi_instance_t vmi, uint32_t dtb, uint32_t vaddr, page_info_t *info) {
    info->arm_aarch32.fld_location = (dtb & VMI_BIT_MASK(14,31)) | (first_level_table_index(vaddr) << 2);
    uint32_t fld_v;
    if(VMI_SUCCESS == vmi_read_32_pa(vmi, info->arm_aarch32.fld_location, &fld_v)) {
        info->arm_aarch32.fld_value = fld_v;
    }
}

// 2nd Level Page Table Index (Course Pages)
static inline
uint32_t coarse_second_level_table_index(uint32_t vaddr) {
    return (vaddr>>12) & VMI_BIT_MASK(0,7);
}

// 2nd Level Page Table Descriptor (Course Pages)
static inline
void get_coarse_second_level_descriptor(vmi_instance_t vmi, uint32_t vaddr, page_info_t *info) {
    info->arm_aarch32.sld_location = (info->arm_aarch32.fld_value & VMI_BIT_MASK(10,31)) | (coarse_second_level_table_index(vaddr) << 2);
    uint32_t sld_v;
    if(VMI_SUCCESS == vmi_read_32_pa(vmi, info->arm_aarch32.sld_location, &sld_v)) {
        info->arm_aarch32.sld_value = sld_v;
    }
}

// 2nd Level Page Table Index (Fine Pages)
static inline
uint32_t fine_second_level_table_index(uint32_t vaddr) {
    return (vaddr>>10) & VMI_BIT_MASK(0,9);
}

// 2nd Level Page Table Descriptor (Fine Pages)
static inline
void get_fine_second_level_descriptor(vmi_instance_t vmi, uint32_t vaddr, page_info_t *info) {
    info->arm_aarch32.sld_location = (info->arm_aarch32.fld_value & VMI_BIT_MASK(12,31)) | fine_second_level_table_index(vaddr) | 0b11;
    uint32_t sld_v;
    if(VMI_SUCCESS == vmi_read_32_pa(vmi, info->arm_aarch32.sld_location, &sld_v)) {
        info->arm_aarch32.sld_value = sld_v;
    }
}

// Based on ARM Reference Manual
// Chapter B4 Virtual Memory System Architecture
// B4.7 Hardware page table translation
addr_t v2p_aarch32 (vmi_instance_t vmi,
    addr_t dtb,
    addr_t vaddr,
    page_info_t *info)
{

    dbprint(VMI_DEBUG_PTLOOKUP, "--ARM AArch32 PTLookup: vaddr = 0x%.16"PRIx64", dtb = 0x%.16"PRIx64"\n", vaddr, dtb);

    get_first_level_descriptor(vmi, dtb, vaddr, info);

    dbprint(VMI_DEBUG_PTLOOKUP, "--ARM AArch32 PTLookup: fld_location = 0x%"PRIx32"\n", info->arm_aarch32.fld_location);
    dbprint(VMI_DEBUG_PTLOOKUP, "--ARM AArch32 PTLookup: fld_value = 0x%"PRIx32"\n", info->arm_aarch32.fld_value);

    switch(info->arm_aarch32.fld_value & VMI_BIT_MASK(0,1)) {

        case 0b01: {

            dbprint(VMI_DEBUG_PTLOOKUP, "--ARM AArch32 PTLookup: the entry gives the physical address of a coarse second-level table\n");

            get_coarse_second_level_descriptor(vmi, vaddr, info);

            dbprint(VMI_DEBUG_PTLOOKUP, "--ARM AArch32 PTLookup: l2d = 0x%"PRIx32"\n", info->arm_aarch32.sld_value);

            switch(info->arm_aarch32.sld_value & VMI_BIT_MASK(0,1)) {
                case 0b01:
                    // large page
                    info->size = VMI_PS_64KB;
                    info->paddr = (info->arm_aarch32.sld_value & VMI_BIT_MASK(16,31)) | (vaddr & VMI_BIT_MASK(0,15));
                    break;
                case 0b10:
                case 0b11:
                    // small page
                    info->size = VMI_PS_4KB;
                    info->paddr = (info->arm_aarch32.sld_value & VMI_BIT_MASK(12,31)) | (vaddr & VMI_BIT_MASK(0,11));
                default:
                    break;
            }

            break;
        }

        case 0b10: {

            if(!VMI_GET_BIT(info->arm_aarch32.fld_value, 18)) {
                dbprint(VMI_DEBUG_PTLOOKUP, "--ARM AArch32 PTLookup: the entry is a section descriptor for its associated modified virtual addresses\n");
                info->size = VMI_PS_1MB;
                info->paddr = (info->arm_aarch32.fld_value & VMI_BIT_MASK(20,31)) | (vaddr & VMI_BIT_MASK(0,19));
            } else {
                dbprint(VMI_DEBUG_PTLOOKUP, "--ARM AArch32 PTLookup: the entry is a supersection descriptor for its associated modified virtual addresses\n");
                // TODO: supersections are unsupported right now (breaks ptlookup when included)
                //info->size = VMI_PS_16MB;
                //info->paddr = get_bits_31to24(info->l1_v) | get_bits_23to0(vaddr);
            }

            break;
        }

        case 0b11: {

            dbprint(VMI_DEBUG_PTLOOKUP, "--ARM AArch32 PTLookup: the entry gives the physical address of a fine second-level table\n");

            get_fine_second_level_descriptor(vmi, vaddr, info);

            dbprint(VMI_DEBUG_PTLOOKUP, "--ARM AArch32 PTLookup: sld = 0x%"PRIx32"\n", info->arm_aarch32.sld_value);

            switch(info->arm_aarch32.fld_value & VMI_BIT_MASK(0,1)) {
                case 0b01:
                    // large page
                    info->size = VMI_PS_64KB;
                    info->paddr = (info->arm_aarch32.sld_value & VMI_BIT_MASK(16,31)) | (vaddr & VMI_BIT_MASK(0,15));
                    break;
                case 0b10:
                    // small page
                    info->size = VMI_PS_4KB;
                    info->paddr = (info->arm_aarch32.sld_value & VMI_BIT_MASK(12,31)) | (vaddr & VMI_BIT_MASK(0,11));
                    break;
                case 0b11:
                    // tiny page
                    info->size = VMI_PS_1KB;
                    info->paddr = (info->arm_aarch32.sld_value & VMI_BIT_MASK(10,31)) | (vaddr & VMI_BIT_MASK(0,9));
                    break;
                default:
                    break;
            }

            break;
        }

        default:
            break;
    }

    dbprint(VMI_DEBUG_PTLOOKUP, "--ARM PTLookup: PA = 0x%"PRIx64"\n", info->paddr);
    return info->paddr;
}

GSList* get_va_pages_aarch32(vmi_instance_t vmi, addr_t dtb) {
    //TODO: investigate best method to loop over all tables
    return NULL;
}

status_t aarch32_init(vmi_instance_t vmi) {

    if(!vmi->arch_interface) {
        vmi->arch_interface = safe_malloc(sizeof(struct arch_interface));
        bzero(vmi->arch_interface, sizeof(struct arch_interface));
    }

    vmi->arch_interface->v2p = v2p_aarch32;
    vmi->arch_interface->get_va_pages = get_va_pages_aarch32;

    return VMI_SUCCESS;
}
