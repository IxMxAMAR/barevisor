#include <stdio.h>
#include <intrin.h>
#include <string.h>

int main() {
    int regs[4];

    printf("=== Deep Hypervisor Probe ===\n\n");

    // CPUID leaf 0 — basic info
    __cpuid(regs, 0);
    printf("CPUID.0  max leaf: %d\n", regs[0]);

    // CPUID leaf 1 — feature flags
    __cpuid(regs, 1);
    printf("CPUID.1  ECX: %08X\n", regs[2]);
    printf("  bit 5  (VMX):     %d\n", (regs[2] >> 5) & 1);
    printf("  bit 31 (HV):      %d\n", (regs[2] >> 31) & 1);

    // CPUID leaf 0x40000000 — hypervisor vendor
    __cpuid(regs, 0x40000000);
    char vendor[13] = {0};
    memcpy(vendor + 0, &regs[1], 4);
    memcpy(vendor + 4, &regs[2], 4);
    memcpy(vendor + 8, &regs[3], 4);
    printf("CPUID.40000000  max: %08X  vendor: \"%s\"\n", regs[0], vendor);

    // CPUID leaf 0x40000001 — hypervisor interface
    __cpuid(regs, 0x40000001);
    char iface[5] = {0};
    memcpy(iface, &regs[0], 4);
    printf("CPUID.40000001  interface: \"%s\" (%08X)\n", iface, regs[0]);

    // CPUID leaf 0x40000003 — hypervisor features (if Hyper-V)
    __cpuid(regs, 0x40000003);
    printf("CPUID.40000003  EAX:%08X EBX:%08X ECX:%08X EDX:%08X\n",
           regs[0], regs[1], regs[2], regs[3]);

    // Try reading IA32_VMX_BASIC via CPUID (can't rdmsr from usermode)
    // Check if VMX is actually usable
    __cpuid(regs, 1);
    int vmx = (regs[2] >> 5) & 1;
    int hv = (regs[2] >> 31) & 1;

    printf("\n=== Verdict ===\n");
    if (hv && strcmp(vendor, "Microsoft Hv") == 0) {
        printf("Windows VBS/Hyper-V is ACTIVE (even with all disables!)\n");
        printf("This will block barevisor from taking VMX root.\n");
    } else if (hv && strncmp(vendor, "Bare", 4) == 0) {
        printf("BAREVISOR IS RUNNING! Stealth partial (HV bit exposed).\n");
    } else if (!hv && strncmp(vendor, "Bare", 4) == 0) {
        printf("BAREVISOR IS RUNNING AND FULLY STEALTHED!\n");
    } else if (!hv && vmx) {
        printf("CLEAN — No hypervisor, VMX available. Ready for barevisor.\n");
    } else if (!hv && !vmx) {
        printf("CLEAN — No hypervisor, no VMX (check BIOS VT-x setting).\n");
    } else {
        printf("Unknown state: HV=%d VMX=%d vendor=\"%s\"\n", hv, vmx, vendor);
    }

    return 0;
}
