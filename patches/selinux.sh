#!/bin/bash
# SELinux patches for KernelSU / SukiSU on older kernels
# Fixes security_bounded_transition blocking init -> su domain transition

## Patch 1: bypass bounded_transition for su domain
if [ -f security/selinux/ss/services.c ] && ! grep -q "KernelSU: allow transition to su" security/selinux/ss/services.c; then
    sed -i '/int security_bounded_transition/,/read_lock(&policy_rwlock);/{
/read_lock(&policy_rwlock);/i\
	/* KernelSU: allow transition to su domain, bypass bounds check */\
	{\
		struct context *nc = sidtab_search(&sidtab, new_sid);\
		if (nc) {\
			char *name = sym_name(&policydb, SYM_TYPES, nc->type - 1);\
			if (name && strcmp(name, "su") == 0)\
				return 0;\
		}\
	}
}' security/selinux/ss/services.c
    echo "Patched: SELinux bounded_transition bypass for su domain"
fi

## Patch 2: reset AVC cache after applying KernelSU selinux rules
if [ -f KernelSU/kernel/selinux/rules.c ] && ! grep -q "reset_avc_cache" KernelSU/kernel/selinux/rules.c; then
    sed -i '1i\extern void reset_avc_cache(void);' KernelSU/kernel/selinux/rules.c
    sed -i '/apply_kernelsu_rules/,/^}/{
/^}$/i\
	reset_avc_cache();
}' KernelSU/kernel/selinux/rules.c
    echo "Patched: AVC cache reset in KernelSU rules.c"
fi
