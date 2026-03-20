# Playbook: Kernel Module Loading

**MITRE ATT&CK:** T1547.006 — Boot or Logon Autostart Execution: Kernel Modules  
**Severity:** CRITICAL  
**auditd key:** module_loading  

## Trigger
Fires when insmod, rmmod, or modprobe is executed, or when init_module/delete_module syscalls are detected.

## Triage
1. `ausearch -k module_loading --start today -i`
2. List currently loaded modules: `lsmod`
3. Inspect a specific module: `modinfo <module_name>`
4. Check dmesg for suspicious entries: `dmesg | grep -i "module\|taint\|rootkit" | tail -20`
5. Identify actor: `ausearch -k module_loading | grep auid=`

## Containment
- Unload suspicious module: `sudo rmmod <module_name>`
- If rootkit suspected: isolate the host immediately — do not continue operating the system

## Remediation
- Boot from known-good media and perform offline forensic analysis if rootkit is suspected
- Check `/etc/modules` and `/etc/modprobe.d/` for persistence entries

## Post-Incident
- Consider full re-image if rootkit involvement cannot be ruled out
- Update incident timeline with module name, actor, and timestamp
