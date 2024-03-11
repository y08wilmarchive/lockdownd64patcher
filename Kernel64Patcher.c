/*
* Copyright 2020, @Ralph0045
* gcc Kernel64Patcher.c -o Kernel64Patcher
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include "patchfinder64.c"
#include "patchfinder64_friedappleteam.c"

#define GET_OFFSET(kernel_len, x) (x - (uintptr_t) kernel_buf)

#define kMobileKeyBagDisabled 3
#define kMobileKeyBagSuccess (0)
#define kMobileKeyBagError (-1)
#define kMobileKeyBagDeviceLockedError (-2)

// iOS 8 arm64
int get__MKBDeviceUnlockedSinceBoot_patch_ios8(void* kernel_buf,size_t kernel_len) {
    // search 1f 00 00 71 e8 17 9f 1a 88 02 00 b9 60 06 00 34
    // .. heres one line before the ent_loc
    // bl 0x1000541cc
    // .. and heres what we are searching for
    // cmp w0, #0
    // cset w8, eq
    // str w8, [x20]
    // cbz w0, 0x100020038
    // we need to step one line back and find the sub the bl is calling
    uint8_t search[] = { 0x1F, 0x00, 0x00, 0x71, 0xE8, 0x17, 0x9F, 0x1A, 0x88, 0x02, 0x00, 0xB9, 0x60, 0x06, 0x00, 0x34 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"_MKBDeviceUnlockedSinceBoot\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"_MKBDeviceUnlockedSinceBoot\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)find_last_insn_matching_64(0, kernel_buf, kernel_len, ent_loc, insn_is_bl_64);
    if(!xref_stuff) {
        printf("%s: Could not find \"_MKBDeviceUnlockedSinceBoot\" xref\n",__FUNCTION__);
        return -1;
    }
    addr_t br_addr = (addr_t)find_br_address_with_bl_64(0, kernel_buf, kernel_len, xref_stuff);
    if(!br_addr) {
        printf("%s: Could not find \"_MKBDeviceUnlockedSinceBoot\" br_addr\n",__FUNCTION__);
        return -1;
    }
    // nop -> mov w0, 0x1
    // ldr x16, _MKBDeviceUnlockedSinceBoot -> ret
    // br x16
    br_addr = (addr_t)GET_OFFSET(kernel_len, br_addr);
    xref_stuff = br_addr - 0x4; // step back to ldr x16, _MKBDeviceUnlockedSinceBoot
    xref_stuff = xref_stuff - 0x4; // step back to nop
    printf("%s: Found \"_MKBDeviceUnlockedSinceBoot\" beg_func at %p\n\n", __FUNCTION__,GET_OFFSET(kernel_len,xref_stuff));
    printf("%s: Patching \"_MKBDeviceUnlockedSinceBoot\" at %p\n\n", __FUNCTION__,GET_OFFSET(kernel_len,xref_stuff));
    // 1 is yes, 0 is no
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x52800020; // mov w0, 0x1
    *(uint32_t *) (kernel_buf + xref_stuff + 0x4) = 0xD65F03C0; // ret
    return 0;
}

// iOS 8 arm64
int get__MKBGetDeviceLockState_patch_ios8(void* kernel_buf,size_t kernel_len) {
    // search c0 01 00 54 1f 05 00 71 a1 03 00 54 00 00 80 d2
    // .. heres what we are searching for
    // cmp w0, #0
    // cset w8, eq
    // str w8, [x20]
    // cbz w0, 0x100020038
    // .. heres one line after
    // bl _MKBGetDeviceLockState
    // we need to find the insn matching bl and then find the sub the bl is calling
    uint8_t search[] = { 0xC0, 0x01, 0x00, 0x54, 0x1F, 0x05, 0x00, 0x71, 0xA1, 0x03, 0x00, 0x54, 0x00, 0x00, 0x80, 0xD2 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"_MKBGetDeviceLockState\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"_MKBGetDeviceLockState\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)find_next_insn_matching_64(0, kernel_buf, kernel_len, ent_loc, insn_is_bl_64);
    if(!xref_stuff) {
        printf("%s: Could not find \"_MKBGetDeviceLockState\" xref\n",__FUNCTION__);
        return -1;
    }
    addr_t br_addr = (addr_t)find_br_address_with_bl_64(0, kernel_buf, kernel_len, xref_stuff);
    if(!br_addr) {
        printf("%s: Could not find \"_MKBGetDeviceLockState\" br_addr\n",__FUNCTION__);
        return -1;
    }
    // nop -> mov w0, 0x3
    // ldr x16, _MKBGetDeviceLockState -> ret
    // br x16
    br_addr = (addr_t)GET_OFFSET(kernel_len, br_addr);
    xref_stuff = br_addr - 0x4; // step back to ldr x16, _MKBGetDeviceLockState
    xref_stuff = xref_stuff - 0x4; // step back to nop
    printf("%s: Found \"_MKBGetDeviceLockState\" beg_func at %p\n\n", __FUNCTION__,GET_OFFSET(kernel_len,xref_stuff));
    printf("%s: Patching \"_MKBGetDeviceLockState\" at %p\n\n", __FUNCTION__,GET_OFFSET(kernel_len,xref_stuff));
    // #define kMobileKeyBagDisabled 3
    // #define kMobileKeyBagSuccess (0)
    // #define kMobileKeyBagError (-1)
    // #define kMobileKeyBagDeviceLockedError (-2)
    // see https://i.imgur.com/N44GhCy.png for explanation
    // if status != kMobileKeyBagDisabled
    //     status = _MKBUnlockDevice(passcodeData, NULL) # which returns kMobileKeyBagDeviceLockedError
    // else
    //     status = kMobileKeyBagSuccess
    // fi
    // if status != kMobileKeyBagSuccess
    //     printf("could not unlock device");
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x52800060; // mov w0, 0x3
    *(uint32_t *) (kernel_buf + xref_stuff + 0x4) = 0xD65F03C0; // ret
    return 0;
}

int main(int argc, char **argv) {
    
    printf("%s: Starting...\n", __FUNCTION__);
    
    FILE* fp = NULL;
    
    if(argc < 4){
        printf("Usage: %s <lockdownd_in> <lockdownd_out> <args>\n",argv[0]);
        printf("\t-u\t\tPatch _MKBDeviceUnlockedSinceBoot (iOS 8 Only)\n");
        printf("\t-l\t\tPatch _MKBGetDeviceLockState (iOS 8 Only)\n");
        
        return 0;
    }
    
    void* kernel_buf;
    size_t kernel_len;
    
    char *filename = argv[1];
    
    fp = fopen(argv[1], "rb");
    if(!fp) {
        printf("%s: Error opening %s!\n", __FUNCTION__, argv[1]);
        return -1;
    }
    
    fseek(fp, 0, SEEK_END);
    kernel_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    kernel_buf = (void*)malloc(kernel_len);
    if(!kernel_buf) {
        printf("%s: Out of memory!\n", __FUNCTION__);
        fclose(fp);
        return -1;
    }
    
    fread(kernel_buf, 1, kernel_len, fp);
    fclose(fp);
    
    if(memmem(kernel_buf,kernel_len,"KernelCacheBuilder",18)) {
        printf("%s: Detected IMG4/IM4P, you have to unpack and decompress it!\n",__FUNCTION__);
        return -1;
    }
    
    if (*(uint32_t*)kernel_buf == 0xbebafeca) {
        printf("%s: Detected fat macho kernel\n",__FUNCTION__);
        memmove(kernel_buf,kernel_buf+28,kernel_len);
    }
    
    init_kernel(0, filename);
    
    for(int i=0;i<argc;i++) {
        if(strcmp(argv[i], "-u") == 0) {
            printf("Kernel: Adding _MKBDeviceUnlockedSinceBoot patch...\n");
            get__MKBDeviceUnlockedSinceBoot_patch_ios8(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-l") == 0) {
            printf("Kernel: Adding _MKBGetDeviceLockState patch...\n");
            get__MKBGetDeviceLockState_patch_ios8(kernel_buf,kernel_len);
        }
    }
    
    term_kernel();
    
    /* Write patched kernel */
    printf("%s: Writing out patched file to %s...\n", __FUNCTION__, argv[2]);
    
    fp = fopen(argv[2], "wb+");
    if(!fp) {
        printf("%s: Unable to open %s!\n", __FUNCTION__, argv[2]);
        free(kernel_buf);
        return -1;
    }
    
    fwrite(kernel_buf, 1, kernel_len, fp);
    fflush(fp);
    fclose(fp);
    
    free(kernel_buf);
    
    printf("%s: Quitting...\n", __FUNCTION__);
    
    return 0;
}
