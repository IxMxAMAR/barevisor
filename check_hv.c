#include <stdio.h>
#include <intrin.h>
#include <string.h>

int main() {
    int regs[4];  // EAX, EBX, ECX, EDX

    // Check CPUID leaf 1 — hypervisor present bit
    __cpuid(regs, 1);
    int hv_present = (regs[2] >> 31) & 1;
    int vmx_bit = (regs[2] >> 5) & 1;

    printf("=== Aria Hypervisor Check ===\n\n");
    printf("CPUID.1.ECX[31] (HV present):  %s\n", hv_present ? "YES (EXPOSED!)" : "NO (hidden - good)");
    printf("CPUID.1.ECX[5]  (VMX support): %s\n", vmx_bit ? "YES (EXPOSED!)" : "NO (hidden - good)");

    // Check CPUID leaf 0x40000000 — hypervisor vendor
    __cpuid(regs, 0x40000000);
    char vendor[13] = {0};
    memcpy(vendor + 0, &regs[1], 4);  // EBX
    memcpy(vendor + 4, &regs[2], 4);  // ECX
    memcpy(vendor + 8, &regs[3], 4);  // EDX

    int is_barevisor = (memcmp(vendor, "Barevisor!", 10) == 0);

    printf("CPUID.40000000  (HV vendor):   \"%s\"\n", vendor);
    printf("\n");

    if (is_barevisor && !hv_present && !vmx_bit) {
        printf(">>> HYPERVISOR IS ACTIVE AND FULLY STEALTHED <<<\n");
        printf("    Barevisor running in VMX root mode\n");
        printf("    Hypervisor undetectable via CPUID\n");
    } else if (is_barevisor) {
        printf(">>> HYPERVISOR ACTIVE but STEALTH INCOMPLETE <<<\n");
        if (hv_present) printf("    WARNING: HV present bit is exposed!\n");
        if (vmx_bit)    printf("    WARNING: VMX bit is exposed!\n");
    } else {
        printf(">>> NO HYPERVISOR DETECTED <<<\n");
        printf("    Barevisor is not running\n");
    }

    return 0;
}
