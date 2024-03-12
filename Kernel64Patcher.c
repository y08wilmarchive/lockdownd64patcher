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
    uint8_t ios8[] = { 0x1F, 0x00, 0x00, 0x71, 0xE8, 0x17, 0x9F, 0x1A, 0x88, 0x02, 0x00, 0xB9, 0x60, 0x06, 0x00, 0x34 };
    void* ent_loc = memmem(kernel_buf, kernel_len, ios8, sizeof(ios8) / sizeof(*ios8));
    if (!ent_loc) {
        // search 14 00 80 d2 1f 00 00 31 e8 17 9f 1a 68 02 00 b9 20 05 00 34
        // .. heres one line before the ent_loc
        // bl 0x100065e24
        // .. and heres what we are searching for
        // mov x20, #0
        // cmn w0, #0
        // cset w8, eq
        // str w8, [x19]
        // cbz w0, 0x100027ad4
        // we need to step one line back and find the sub the bl is calling
        uint8_t ios7[] = { 0x14, 0x00, 0x80, 0xd2, 0x1f, 0x00, 0x00, 0x31, 0xe8, 0x17, 0x9f, 0x1a, 0x68, 0x02, 0x00, 0xb9, 0x20, 0x05, 0x00, 0x34 };
        ent_loc = memmem(kernel_buf, kernel_len, ios7, sizeof(ios7) / sizeof(*ios7));
        if (!ent_loc) {
            printf("%s: Could not find \"_MKBDeviceUnlockedSinceBoot\" patch\n",__FUNCTION__);
            return -1;
        }
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
    // b.eq 0x100012394
    // cmp w8, #0x1
    // b.ne 0x1000123d8
    // mov x0, #0
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

// iOS 8 arm64
int get_set_brick_state_patch_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search "_set_brick_state" str
    // ... and heres some notable lines of code before that
    // bl 0x10000f298
    // cbnz w0, 0x10000c80c
    // take note that we are searching by 00 94 and not A2 02 00 94 at the start
    // this means to get to the next line we need to add 0x2 not 0x4
    // we need to make bl 0x10000f298 a mov w0, 0x1
    // because cbnz w0, 0x10000c80c is checking register w0
    char* str = "_set_brick_state";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str));
    if(!ent_loc) {
        printf("%s: Could not find \"_set_brick_state\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"_set_brick_state\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    uint32_t* literal_ref = find_literal_ref_64(0, kernel_buf, kernel_len, (uint32_t*)kernel_buf, GET_OFFSET(kernel_len,ent_loc));
    if(!literal_ref) {
       printf("%s: Could not find \"_set_brick_state\" literal_ref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"_set_brick_state\" literal_ref at %p\n\n", __FUNCTION__,(void*)(literal_ref));
    addr_t bl_addr = (addr_t)find_last_insn_matching_64(0, kernel_buf, kernel_len, literal_ref, insn_is_bl_64);
    if(!bl_addr) {
        printf("%s: Could not find \"_set_brick_state\" bl addr\n",__FUNCTION__);
        return -1;
    }
    bl_addr = (addr_t)GET_OFFSET(kernel_len, bl_addr);
    printf("%s: Patching \"_set_brick_state\" at %p\n\n", __FUNCTION__,(void*)(bl_addr));
    // 0xD503201F is nop
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result, which can be used after the = sign to make this a nop
    // but this patch requires bl 0x10000caa4 to be mov w0, 0x1 which is 0x20 0x00 0x80 0x52 or 0x52800020 in little endian
    *(uint32_t *) (kernel_buf + bl_addr) = 0x52800020; // mov w0, 0x1
    return 0;
}

// iOS 8 arm64
int get_ar_loadAndVerify_patch_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char* str = "ar_loadAndVerify";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str));
    if(!ent_loc) {
        printf("%s: Could not find \"ar_loadAndVerify\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"ar_loadAndVerify\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"ar_loadAndVerify\" xref\n",__FUNCTION__);
        xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
        return -1;
    }
    printf("%s: Found \"ar_loadAndVerify\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t beg_func = bof64(kernel_buf,0,xref_stuff);
    if(!beg_func) {
       printf("%s: Could not find \"ar_loadAndVerify\" funcbegin insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching \"ar_loadAndVerify\" at %p\n\n", __FUNCTION__,(void*)(beg_func));
    // 0xD503201F is nop
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result
    *(uint32_t *) (kernel_buf + beg_func) = 0x52800020; // mov w0, 0x1
    *(uint32_t *) (kernel_buf + beg_func + 0x4) = 0xD65F03C0; // ret
    return 0;
}

// iOS 7 arm64
int get_verify_ar_patch_ios7(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__); // e2030032e00315aae10314aa
    // search e2 03 00 32 e0 03 15 aa e1 03 14 aa
    // .. heres what we are searching for
    // orr w2, wzr, #0x1
    // mov x0, x21
    // mov x1, x20
    // .. and heres one line after
    // bl _verify_ar
    // we need to find the bl and patch the func it is calling to return 0x1
    uint8_t search[] = { 0xe2, 0x03, 0x00, 0x32, 0xe0, 0x03, 0x15, 0xaa, 0xe1, 0x03, 0x14, 0xaa };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"verify_ar\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"verify_ar\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t bl_addr = (addr_t)find_next_insn_matching_64(0, kernel_buf, kernel_len, ent_loc, insn_is_bl_64);
    if(!bl_addr) {
        printf("%s: Could not find \"verify_ar\" bl addr\n",__FUNCTION__);
        return -1;
    }
    addr_t br_addr = (addr_t)find_br_address_with_bl_64(0, kernel_buf, kernel_len, bl_addr);
    if(!br_addr) {
        printf("%s: Could not find \"verify_ar\" br_addr\n",__FUNCTION__);
        return -1;
    }
    // nop -> mov w0, 0x1
    // ldr x16, verify_ar -> ret
    // br x16
    br_addr = (addr_t)GET_OFFSET(kernel_len, br_addr);
    addr_t xref_stuff = br_addr - 0x4; // step back to ldr x16, verify_ar
    xref_stuff = xref_stuff - 0x4; // step back to nop
    printf("%s: Found \"verify_ar\" beg_func at %p\n\n", __FUNCTION__,GET_OFFSET(kernel_len,xref_stuff));
    printf("%s: Patching \"verify_ar\" at %p\n\n", __FUNCTION__,GET_OFFSET(kernel_len,xref_stuff));
    // 1 is yes, 0 is no
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x52800020; // mov w0, 0x1
    *(uint32_t *) (kernel_buf + xref_stuff + 0x4) = 0xD65F03C0; // ret
    return 0;
}

// iOS 8 arm64
int get_handle_deactivate_patch_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char* str = "handle_deactivate";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str));
    if(!ent_loc) {
        printf("%s: Could not find \"handle_deactivate\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"handle_deactivate\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
       printf("%s: Could not find \"handle_deactivate\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"handle_deactivate\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t beg_func = bof64(kernel_buf,0,xref_stuff);
    if(!beg_func) {
       printf("%s: Could not find \"handle_deactivate\" funcbegin insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching \"handle_deactivate\" at %p\n\n", __FUNCTION__,(void*)(beg_func));
    // 0xD503201F is nop
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result
    *(uint32_t *) (kernel_buf + beg_func) = 0x52800000; // mov w0, 0x0
    *(uint32_t *) (kernel_buf + beg_func + 0x4) = 0xD65F03C0; // ret
    return 0;
}

// iOS 8 arm64
int get_check_build_expired_patch_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char* str = "check_build_expired";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str));
    if(!ent_loc) {
        printf("%s: Could not find \"check_build_expired\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"check_build_expired\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
       printf("%s: Could not find \"check_build_expired\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"check_build_expired\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t beg_func = bof64(kernel_buf,0,xref_stuff);
    if(!beg_func) {
       printf("%s: Could not find \"check_build_expired\" funcbegin insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching \"check_build_expired\" at %p\n\n", __FUNCTION__,(void*)(beg_func));
    // 0xD503201F is nop
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result
    *(uint32_t *) (kernel_buf + beg_func) = 0x52800000; // mov w0, 0x0
    *(uint32_t *) (kernel_buf + beg_func + 0x4) = 0xD65F03C0; // ret
    return 0;
}

int main(int argc, char **argv) {
    
    printf("%s: Starting...\n", __FUNCTION__);
    
    FILE* fp = NULL;
    
    if(argc < 4){
        printf("Usage: %s <lockdownd_in> <lockdownd_out> <args>\n",argv[0]);
        printf("\t-u\t\tPatch _MKBDeviceUnlockedSinceBoot (iOS 7& 8 Only)\n");
        printf("\t-l\t\tPatch _MKBGetDeviceLockState (iOS 7& 8 Only)\n");
        printf("\t-g\t\tPatch _set_brick_state (iOS 7& 8 Only)\n");
        printf("\t-b\t\tPatch ar_loadAndVerify (iOS 7& 8 Only)\n");
        printf("\t-c\t\tPatch handle_deactivate (iOS 7& 8 Only)\n");
        printf("\t-d\t\tPatch check_build_expired (iOS 7& 8 Only)\n");
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
        if(strcmp(argv[i], "-g") == 0) {
            printf("Kernel: Adding _set_brick_state patch...\n");
            get_set_brick_state_patch_ios8(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-b") == 0) {
            printf("Kernel: Adding ar_loadAndVerify patch...\n");
            get_verify_ar_patch_ios7(kernel_buf,kernel_len);
            get_ar_loadAndVerify_patch_ios8(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-c") == 0) {
            printf("Kernel: Adding handle_deactivate patch...\n");
            get_handle_deactivate_patch_ios8(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-d") == 0) {
            printf("Kernel: Adding check_build_expired patch...\n");
            get_check_build_expired_patch_ios8(kernel_buf,kernel_len);
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
