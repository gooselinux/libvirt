# -*- rpm-spec -*-

# A client only build will create a libvirt.so only containing
# the generic RPC driver, and test driver and no libvirtd
# Default to a full server + client build
%define client_only        0

# Now turn off server build in certain cases

# RHEL-5 builds are client-only for s390, ppc
%if 0%{?rhel} == 5
%ifnarch i386 i586 i686 x86_64 ia64
%define client_only        1
%endif
%endif

# Disable all server side drivers if client only build requested
%if %{client_only}
%define server_drivers     0
%else
%define server_drivers     1
%endif


# Now set the defaults for all the important features, independent
# of any particular OS

# First the daemon itself
%define with_libvirtd      0%{!?_without_libvirtd:%{server_drivers}}
%define with_avahi         0%{!?_without_avahi:%{server_drivers}}

# Then the hypervisor drivers that run on local host
%define with_xen           0%{!?_without_xen:%{server_drivers}}
%define with_qemu          0%{!?_without_qemu:%{server_drivers}}
%define with_openvz        0%{!?_without_openvz:%{server_drivers}}
%define with_lxc           0%{!?_without_lxc:%{server_drivers}}
%define with_vbox          0%{!?_without_vbox:%{server_drivers}}
%define with_uml           0%{!?_without_uml:%{server_drivers}}
%define with_xenapi        0%{!?_without_xenapi:%{server_drivers}}
# XXX this shouldn't be here, but it mistakenly links into libvirtd
%define with_one           0%{!?_without_one:%{server_drivers}}

# Then the hypervisor drivers that talk a native remote protocol
%define with_phyp          0%{!?_without_phyp:1}
%define with_esx           0%{!?_without_esx:1}
%define with_vmware        0%{!?_without_vmware:1}

# Then the secondary host drivers
%define with_network       0%{!?_without_network:%{server_drivers}}
%define with_storage_fs    0%{!?_without_storage_fs:%{server_drivers}}
%define with_storage_lvm   0%{!?_without_storage_lvm:%{server_drivers}}
%define with_storage_iscsi 0%{!?_without_storage_iscsi:%{server_drivers}}
%define with_storage_disk  0%{!?_without_storage_disk:%{server_drivers}}
%define with_storage_mpath 0%{!?_without_storage_mpath:%{server_drivers}}
%define with_numactl       0%{!?_without_numactl:%{server_drivers}}
%define with_selinux       0%{!?_without_selinux:%{server_drivers}}

# A few optional bits off by default, we enable later
%define with_polkit        0%{!?_without_polkit:0}
%define with_capng         0%{!?_without_capng:0}
%define with_netcf         0%{!?_without_netcf:0}
%define with_udev          0%{!?_without_udev:0}
%define with_hal           0%{!?_without_hal:0}
%define with_yajl          0%{!?_without_yajl:0}
%define with_nwfilter      0%{!?_without_nwfilter:0}
%define with_libpcap       0%{!?_without_libpcap:0}
%define with_macvtap       0%{!?_without_macvtap:0}
%define with_libnl         0%{!?_without_libnl:0}
%define with_audit         0%{!?_without_audit:0}
%define with_dtrace        0%{!?_without_dtrace:0}
%define with_cgconfig      0%{!?_without_cgconfig:0}

# Non-server/HV driver defaults which are always enabled
%define with_python        0%{!?_without_python:1}
%define with_sasl          0%{!?_without_sasl:1}


# Finally set the OS / architecture specific special cases

# Xen is available only on i386 x86_64 ia64
%ifnarch i386 i586 i686 x86_64 ia64
%define with_xen 0
%endif

# Numactl is not available on s390[x]
%ifarch s390 s390x
%define with_numactl 0
%endif

# RHEL doesn't ship OpenVZ, VBox, UML, OpenNebula, PowerHypervisor,
# VMWare, or libxenserver (xenapi)
%if 0%{?rhel}
%define with_openvz 0
%define with_vbox 0
%define with_uml 0
%define with_one 0
%define with_phyp 0
%define with_vmware 0
%define with_xenapi 0
%endif

# RHEL-5 has restricted QEMU to x86_64 only and is too old for LXC
%if 0%{?rhel} == 5
%ifnarch x86_64
%define with_qemu 0
%endif
%define with_lxc 0
%endif

# RHEL-6 has restricted QEMU to x86_64 only, stopped including Xen
# on all archs. Other archs all have LXC available though
%if 0%{?rhel} >= 6
%ifnarch x86_64
%define with_qemu 0
%endif
%define with_xen 0
%endif

# Fedora doesn't have any QEMU on ppc64 - only ppc
%if 0%{?fedora}
%ifarch ppc64
%define with_qemu 0
%endif
%endif

# PolicyKit was introduced in Fedora 8 / RHEL-6 or newer
%if 0%{?fedora} >= 8 || 0%{?rhel} >= 6
%define with_polkit    0%{!?_without_polkit:1}
%endif

# libcapng is used to manage capabilities in Fedora 12 / RHEL-6 or newer
%if 0%{?fedora} >= 12 || 0%{?rhel} >= 6
%define with_capng     0%{!?_without_capng:1}
%endif

# netcf is used to manage network interfaces in Fedora 12 / RHEL-6 or newer
%if 0%{?fedora} >= 12 || 0%{?rhel} >= 6
%define with_netcf     0%{!?_without_netcf:%{server_drivers}}
%endif

# udev is used to manage host devices in Fedora 12 / RHEL-6 or newer
%if 0%{?fedora} >= 12 || 0%{?rhel} >= 6
%define with_udev     0%{!?_without_udev:%{server_drivers}}
%else
%define with_hal       0%{!?_without_hal:%{server_drivers}}
%endif

# Enable yajl library for JSON mode with QEMU
%if 0%{?fedora} >= 13 || 0%{?rhel} >= 6
%define with_yajl     0%{!?_without_yajl:%{server_drivers}}
%endif

# Enable libpcap library
%if %{with_qemu}
%define with_nwfilter 0%{!?_without_nwfilter:%{server_drivers}}
%define with_libpcap  0%{!?_without_libpcap:%{server_drivers}}
%define with_macvtap  0%{!?_without_macvtap:%{server_drivers}}
%endif

%if %{with_macvtap}
%define with_libnl 1
%endif

%if 0%{?fedora} >= 11 || 0%{?rhel} >= 5
%define with_audit    0%{!?_without_audit:1}
%endif

%if 0%{?fedora} >= 13 || 0%{?rhel} >= 6
%define with_dtrace 1
%endif

# Pull in cgroups config system
%if 0%{?fedora} >= 12 || 0%{?rhel} >= 6
%if %{with_qemu} || %{with_lxc}
%define with_cgconfig 0%{!?_without_cgconfig:1}
%endif
%endif

# Force QEMU to run as non-root
%if 0%{?fedora} >= 12 || 0%{?rhel} >= 6
%define qemu_user  qemu
%define qemu_group  qemu
%else
%define qemu_user  root
%define qemu_group  root
%endif


# The RHEL-5 Xen package has some feature backports. This
# flag is set to enable use of those special bits on RHEL-5
%if 0%{?rhel} == 5
%define with_rhel5  1
%else
%define with_rhel5  0
%endif


# there's no use compiling the network driver without
# the libvirt daemon
%if ! %{with_libvirtd}
%define with_network 0
%endif

Summary: Library providing a simple virtualization API
Name: libvirt
Version: 0.8.7
Release: 18%{?dist}%{?extra_release}
License: LGPLv2+
Group: Development/Libraries
Source: http://libvirt.org/sources/libvirt-%{version}.tar.gz

# RHEL only
Patch1: libvirt-Turn-on-JSON-mode-and-netdev-usage-for-RHEL6-binary.patch
Patch3: libvirt-Support-password-expiry-in-the-QEMU-driver.patch
Patch4: libvirt-Emit-graphics-events-when-a-SPICE-client-connects-disconnects.patch
Patch5: libvirt-Support-seemless-migration-of-SPICE-graphics-clients.patch
Patch6: libvirt-Switch-to-private-redhat-namespace-for-QMP-I-O-error-reason.patch
Patch7: libvirt-Support-virtio-disk-hotplug-in-JSON-mode.patch

# Upstream
Patch9: libvirt-bridge-Fix-generation-of-dnsmasq-s-dhcp-hostsfile-option.patch
Patch10: libvirt-qemu-Watchdog-IB700-is-not-a-PCI-device.patch
Patch11: libvirt-Improve-error-reporting-when-parsing-dhcp-info-for-virtual-networks.patch
Patch12: libvirt-Don-t-chown-qemu-saved-image-back-to-root-after-save-if-dynamic_ownership-0.patch
Patch13: libvirt-daemon-Fix-core-dumps-if-unix_sock_group-is-set.patch
Patch14: libvirt-cpu-Add-support-for-Westmere-CPU-model.patch
Patch15: libvirt-Add-XML-config-switch-to-enable-disable-vhost-net-support.patch
Patch16: libvirt-util-add-missing-string-integer-conversion-functions.patch
Patch17: libvirt-Enable-tuning-of-qemu-network-tap-device-sndbuf-size.patch
Patch18: libvirt-qemu-convert-capabilities-to-use-virCommand.patch
Patch19: libvirt-qemu-improve-device-flag-parsing.patch
Patch20: libvirt-conf-Move-boot-parsing-into-a-separate-function.patch
Patch21: libvirt-Introduce-per-device-boot-element.patch
Patch22: libvirt-qemu-Support-per-device-boot-ordering.patch
Patch23: libvirt-tests-Add-tests-for-per-device-boot-elements.patch
Patch24: libvirt-qemu-use-incoming-fd-n-to-avoid-qemu-holding-fd-indefinitely.patch
Patch25: libvirt-conf-Report-error-if-invalid-type-specified-for-character-device.patch
Patch26: libvirt-API-Improve-log-for-domain-related-APIs.patch
Patch27: libvirt-qemu-Reject-SDL-graphic-if-it-s-not-supported-by-qemu.patch
Patch28: libvirt-remote-Don-t-lose-track-of-events-when-callbacks-are-slow.patch
Patch29: libvirt-qemu-Fail-if-per-device-boot-is-used-but-deviceboot-is-not-supported.patch
Patch30: libvirt-qemu-Avoid-sending-STOPPED-event-twice.patch
Patch31: libvirt-virFindFileInPath-only-find-executable-non-directory.patch
Patch32: libvirt-tests-virsh-is-no-longer-in-builddir-src.patch
Patch33: libvirt-qemu-don-t-fail-capabilities-check-on-0.12.x.patch
Patch34: libvirt-event-fix-event-handling-data-race.patch
Patch35: libvirt-qemu-Set-domain-def-transient-at-beginning-of-startup-process.patch
Patch36: libvirt-qemu-Allow-serving-VNC-over-a-unix-domain-socket.patch
Patch37: libvirt-qemu-Add-conf-option-to-auto-setup-VNC-unix-sockets.patch
Patch38: libvirt-Push-unapplied-fixups-for-previous-patch.patch
Patch39: libvirt-qemu-sound-Support-intel-ich6-model.patch
Patch40: libvirt-Do-not-use-virtio-serial-port-0-for-generic-ports.patch
Patch41: libvirt-tests-Fix-virtio-channel-tests.patch
Patch42: libvirt-Add-a-function-to-the-security-driver-API-that-sets-the-label-of-an-open-fd.patch
Patch43: libvirt-Set-SELinux-context-label-of-pipes-used-for-qemu-migration.patch
Patch44: libvirt-Manually-kill-gzip-if-restore-fails-before-starting-qemu.patch
Patch45: libvirt-remote-Add-extra-parameter-pkipath-for-URI.patch
Patch46: libvirt-storage-Round-up-capacity-for-LVM-volume-creation.patch
Patch47: libvirt-qemu-Error-prompt-when-managed-save-a-shutoff-domain.patch
Patch48: libvirt-qemu-report-more-proper-error-for-unsupported-graphics.patch
Patch49: libvirt-libvirt-clarify-virsh-setvcpus-and-setmem-usage-with-active-domains.patch
Patch50: libvirt-docs-fix-incorrect-XML-element-mentioned-by-setmem-text.patch
Patch51: libvirt-docs-expand-the-man-page-text-for-virsh-setmaxmem.patch
Patch52: libvirt-event-fix-event-handling-allocation-crash.patch
Patch53: libvirt-virsh-require-mac-to-avoid-detach-interface-ambiguity.patch
Patch54: libvirt-docs-Add-docs-for-new-extra-parameter-pkipath.patch
Patch55: libvirt-qemu-fix-augeas-support-for-vnc_auto_unix_socket.patch
Patch56: libvirt-qemu-Fix-a-possible-deadlock-in-p2p-migration.patch
Patch57: libvirt-report-error-when-specifying-wrong-desturi.patch
Patch58: libvirt-doc-improve-the-documentation-of-desturi.patch
Patch59: libvirt-qemu-Build-command-line-for-incoming-tunneled-migration.patch
Patch60: libvirt-docs-Update-docs-for-cpu_shares-setting.patch
Patch61: libvirt-Don-t-sleep-in-poll-if-there-is-existing-SASL-decoded-data.patch
Patch62: libvirt-Cancel-migration-if-user-presses-Ctrl-C-when-migration-is-in-progress.patch
Patch63: libvirt-Show-migration-progress.patch
Patch64: libvirt-Force-guest-suspend-at-timeout.patch
Patch65: libvirt-qemu-aio-add-XML-parsing.patch
Patch66: libvirt-qemu-aio-parse-aio-support-from-qemu-help.patch
Patch67: libvirt-qemu-aio-enable-support.patch
Patch68: libvirt-qemu-Retry-JSON-monitor-cont-cmd-on-MigrationExpected-error.patch
Patch69: libvirt-avoid-vm-to-be-deleted-if-qemuConnectMonitor-failed.patch
Patch70: libvirt-Remove-double-close-of-qemu-monitor.patch
Patch71: libvirt-qemu-avoid-double-shutdown.patch
Patch72: libvirt-qemu-Add-shortcut-for-HMP-pass-through.patch
Patch73: libvirt-qemu-Report-more-accurate-error-on-failure-to-attach-device.patch
Patch74: libvirt-qemuBuildDeviceAddressStr-checks-for-QEMUD_CMD_FLAG_PCI_MULTIBUS.patch
Patch75: libvirt-Support-booting-from-hostdev-devices.patch
Patch76: libvirt-qemu-Support-booting-from-hostdev-PCI-devices.patch
Patch77: libvirt-memtune-Let-virsh-know-the-unlimited-value-for-memory-tunables.patch
Patch78: libvirt-docs-document-controller-element.patch
Patch79: libvirt-domain_conf-split-source-data-out-from-ChrDef.patch
Patch80: libvirt-qemu-move-monitor-device-out-of-domain_conf-common-code.patch
Patch81: libvirt-qemu-use-separate-alias-for-chardev-and-associated-device.patch
Patch82: libvirt-tests-handle-backspace-newline-pairs-in-test-input-files.patch
Patch83: libvirt-smartcard-add-XML-support-for-smartcard-device.patch
Patch84: libvirt-smartcard-add-domain-conf-support.patch
Patch85: libvirt-smartcard-check-for-qemu-capability.patch
Patch86: libvirt-smartcard-enable-SELinux-support.patch
Patch87: libvirt-smartcard-turn-on-qemu-support.patch
Patch88: libvirt-spicevmc-support-new-qemu-chardev.patch
Patch89: libvirt-smartcard-add-spicevmc-support.patch
Patch90: libvirt-spicevmc-support-older-device-spicevmc-of-qemu-0.13.0.patch
Patch91: libvirt-Disable-KSM-on-domain-startup.patch
Patch92: libvirt-virsh-added-all-flag-to-freecell-command.patch
Patch93: libvirt-Fix-typo-in-parsing-of-spice-auth-data.patch
Patch94: libvirt-qemu-fix-attach-interface-regression.patch
Patch95: libvirt-cgroup-Enable-cgroup-hierarchy-for-blkio-cgroup.patch
Patch96: libvirt-cgroup-Implement-blkio.weight-tuning-API.patch
Patch97: libvirt-cgroup-Update-XML-Schema-for-new-entries.patch
Patch98: libvirt-qemu-Implement-blkio-tunable-XML-configuration-and-parsing.patch
Patch99: libvirt-LXC-LXC-Blkio-weight-configuration-support.patch
Patch100: libvirt-cgroup-Add-documentation-for-blkiotune-elements.patch
Patch101: libvirt-Support-SCSI-RAID-type-lower-log-level-for-unknown-types.patch
Patch102: libvirt-Only-initialize-cleanup-libpciaccess-once.patch
Patch103: libvirt-Imprint-all-logs-with-version-package-build-information.patch
Patch104: libvirt-qemu-Fix-escape_monitor-escape_shell-command.patch
Patch105: libvirt-libvirt-qemu-Fix-enum-type-declaration.patch
Patch106: libvirt-Fix-cleanup-on-VM-state-after-failed-QEMU-startup.patch
Patch107: libvirt-conf-Fix-XML-generation-for-smartcards.patch
Patch108: libvirt-qemu-ignore-failure-of-qemu-M-on-older-qemu.patch
Patch109: libvirt-Fix-typo-in-setting-up-SPICE-passwords.patch
Patch110: libvirt-virDomainMemoryStats-avoid-null-dereference.patch
Patch111: libvirt-qemu-avoid-NULL-deref-on-error.patch
Patch112: libvirt-qemu-Error-prompt-when-saving-a-shutoff-domain.patch
Patch113: libvirt-storage-Create-enough-volumes-for-mpath-pool.patch
Patch114: libvirt-build-fix-parted-detection-at-configure-time.patch
Patch115: libvirt-storage-Allow-to-delete-device-mapper-disk-partition.patch
Patch116: libvirt-virsh-freecell-all-getting-wrong-NUMA-nodes-count.patch
Patch117: libvirt-Restructure-domain-struct-interface-driver-data-for-easier-expansion.patch
Patch118: libvirt-Add-txmode-attribute-to-interface-XML-for-virtio-backend.patch
Patch119: libvirt-Allow-brAddTap-to-create-a-tap-device-that-is-down.patch
Patch120: libvirt-Give-each-virtual-network-bridge-its-own-fixed-MAC-address.patch
Patch121: libvirt-virsh-replace-vshPrint-with-vshPrintExtra-for-snapshot-list.patch
Patch122: libvirt-802.1Qbh-Delay-IFF_UP-ing-interface-until-migration-final-stage.patch
Patch123: libvirt-network-plug-unininitialized-read-found-by-valgrind.patch
Patch124: libvirt-network-plug-memory-leak.patch
Patch125: libvirt-cpu-plug-memory-leak.patch
Patch126: libvirt-virt-pki-validate-behave-when-CERTTOOL-is-missing.patch
Patch127: libvirt-Fix-off-by-1-in-virFileAbsPath.patch
Patch128: libvirt-nwfilter-reorder-match-extensions-relative-to-state-match.patch
Patch129: libvirt-qemu-avoid-overwriting-error-message.patch
Patch130: libvirt-util-Allow-removing-hash-entries-in-virHashForEach.patch
Patch131: libvirt-qemu-avoid-double-close-on-domain-restore.patch
Patch132: libvirt-qemu-Add-missing-lock-of-virDomainObj-before-calling-virDomainUnref.patch
Patch133: libvirt-qemu-avoid-corruption-of-domain-hashtable-and-misuse-of-freed-domains.patch
Patch134: libvirt-xml-avoid-compiler-warning.patch
Patch135: libvirt-fixes-for-several-memory-leaks.patch
Patch136: libvirt-unlock-eventLoop-before-calling-callback-function.patch
Patch137: libvirt-qemu-Support-vram-for-video-of-qxl-type.patch
Patch138: libvirt-virsh-change-vshCommandOptString-return-type-and-fix-const-correctness.patch
Patch139: libvirt-virsh-Change-option-parsing-functions-to-return-tri-state-information.patch
Patch140: libvirt-qemu-Replace-deprecated-option-of-qemu-img.patch
Patch141: libvirt-storage-Update-qemu-img-flag-checking.patch
Patch142: libvirt-qemu-Setup-infrastructure-for-HMP-passthrough.patch
Patch143: libvirt-qemu-Rename-qemuMonitorCommand-WithFd-as-qemuMonitorHMP.patch
Patch144: libvirt-qemu-Rename-qemuMonitorCommandWithHandler-as-qemuMonitorText.patch
Patch145: libvirt-qemu-Fallback-to-HMP-for-snapshot-commands.patch
Patch146: libvirt-qemu-Escape-snapshot-name-passed-to-save-load-del-vm.patch
Patch147: libvirt-Don-t-overwrite-virRun-error-messages.patch
Patch148: libvirt-qemu-Refactor-qemuDomainSnapshotCreateXML.patch
Patch149: libvirt-qemu-Stop-guest-CPUs-before-creating-a-snapshot.patch
Patch150: libvirt-cgroup-preserve-correct-errno-on-failure.patch
Patch151: libvirt-cgroup-determine-when-skipping-non-devices.patch
Patch152: libvirt-audit-prepare-qemu-for-listing-vm-in-cgroup-audits.patch
Patch153: libvirt-audit-add-qemu-hooks-for-auditing-cgroup-events.patch
Patch154: libvirt-audit-audit-qemu-memory-and-vcpu-adjusments.patch
Patch155: libvirt-audit-audit-qemu-pci-and-usb-device-passthrough.patch
Patch156: libvirt-qemu-only-request-sound-cgroup-ACL-when-required.patch
Patch157: libvirt-audit-tweak-audit-messages-to-match-conventions.patch
Patch158: libvirt-audit-split-cgroup-audit-types-to-allow-more-information.patch
Patch159: libvirt-audit-also-audit-cgroup-controller-path.patch
Patch160: libvirt-audit-rename-remaining-qemu-audit-functions.patch
Patch161: libvirt-cgroup-allow-fine-tuning-of-device-ACL-permissions.patch
Patch162: libvirt-audit-also-audit-cgroup-ACL-permissions.patch
Patch163: libvirt-qemu-support-vhost-in-attach-interface.patch
Patch164: libvirt-qemu-don-t-request-cgroup-ACL-access-for-dev-net-tun.patch
Patch165: libvirt-audit-audit-use-of-dev-net-tun-dev-tapN-dev-vhost-net.patch
Patch166: libvirt-qemu-fix-global-argument-usage.patch
Patch167: libvirt-virsh-Free-stream-when-shutdown-console.patch
Patch168: libvirt-python-Use-hardcoded-python-path-in-libvirt.py.patch
Patch169: libvirt-Add-missing-checks-for-read-only-connections.patch
Patch170: libvirt-audit-eliminate-potential-null-pointer-deref-when-auditing-macvtap-devices.patch
Patch171: libvirt-virsh-Insert-error-messages-to-avoid-a-quiet-abortion-of-commands.patch
Patch172: libvirt-qemu-Check-the-unsigned-integer-overflow.patch
Patch173: libvirt-qemu-use-more-appropriate-error.patch
Patch174: libvirt-bridge_driver-handle-DNS-over-IPv6.patch
Patch175: libvirt-network-driver-Start-dnsmasq-even-if-no-dhcp-ranges-hosts-are-specified.patch
Patch176: libvirt-network-driver-Fix-indentation-from-previous-commit.patch
Patch177: libvirt-network-driver-Use-a-separate-dhcp-leases-file-for-each-network.patch
Patch178: libvirt-storage-Fix-a-problem-which-will-cause-libvirtd-crashed.patch
Patch179: libvirt-Add-a-little-more-debugging-for-async-events.patch
Patch180: libvirt-add-additional-event-debug-points.patch
Patch181: libvirt-Fix-delayed-event-delivery-when-SASL-is-active.patch
Patch182: libvirt-unlock-the-monitor-when-unwatching-the-monitor.patch
Patch183: libvirt-do-not-unref-obj-in-qemuDomainObjExitMonitor.patch
Patch184: libvirt-qemu-respect-locking-rules.patch
Patch185: libvirt-macvtap-log-an-error-if-on-failure-to-connect-to-netlink-socket.patch
Patch186: libvirt-network-driver-log-error-and-abort-network-startup-when-radvd-isn-t-found.patch
Patch187: libvirt-Add-PCI-sysfs-reset-access.patch
Patch188: libvirt-Adjust-some-log-levels-in-udev-driver.patch
Patch189: libvirt-udev-fix-regression-with-qemu-session.patch
Patch190: libvirt-qemu-simplify-monitor-fd-error-handling.patch
Patch191: libvirt-qemu-simplify-PCI-configfd-handling-in-monitor.patch
Patch192: libvirt-util-Fix-return-value-for-virJSONValueFromString-if-it-fails.patch
Patch193: libvirt-qemu-driver-fix-positioning-to-end-of-log-file.patch
Patch194: libvirt-Initialization-error-of-qemuCgroupData-in-Qemu-host-usb-hotplug.patch
Patch195: libvirt-8021Qbh-use-preassociate-rr-during-the-migration-prepare-stage.patch
Patch196: libvirt-Make-error-reporting-in-libvirtd-thread-safe.patch
Patch197: libvirt-daemon-Avoid-resetting-errors-before-they-are-reported.patch
Patch198: libvirt-util-allow-clearing-cloexec-bit.patch
Patch199: libvirt-qemu-fix-restoring-a-compressed-save-image.patch
Patch200: libvirt-qemu-don-t-restore-state-label-twice.patch
Patch201: libvirt-qemu-don-t-restore-label-that-was-never-set.patch
Patch202: libvirt-nwfilter-enable-rejection-of-packets.patch
Patch203: libvirt-Revert-all-previous-error-log-priority-hacks.patch
Patch204: libvirt-Filter-out-certain-expected-error-messages-from-libvirtd.patch
Patch205: libvirt-qemu-unlock-qemu-driver-before-return-from-domain-save.patch
Patch206: libvirt-do-not-send-monitor-command-after-monitor-meet-error.patch
Patch207: libvirt-qemu-Ignore-libvirt-debug-messages-in-qemu-log.patch
Patch208: libvirt-virsh-fix-memtune-s-help-message-for-swap_hard_limit.patch
Patch209: libvirt-virsh-Fix-documentation-for-memtune-command.patch
Patch210: libvirt-docs-fix-typo.patch
Patch211: libvirt-Fix-typo-in-systemtap-tapset-directory-name.patch
Patch212: libvirt-qemu-Ignore-unusable-binaries.patch
Patch213: libvirt-qemu-Support-for-overriding-NPROC-limit.patch
Patch214: libvirt-Don-t-return-an-error-on-failure-to-create-blkio-controller.patch
Patch215: libvirt-Fix-possible-infinite-loop-in-remote-driver.patch
Patch216: libvirt-qemu-Remove-the-managed-state-file-only-if-restoring-succeeded.patch
Patch217: libvirt-docs-tweak-virsh-restore-warning.patch
Patch218: libvirt-network-Fix-NULL-dereference-during-error-recovery.patch
Patch219: libvirt-docs-document-freecell-all.patch
Patch220: libvirt-virsh-list-required-options-first.patch
Patch221: libvirt-virsh-fix-regression-in-parsing-optional-integer.patch
Patch222: libvirt-tests-test-recent-virsh-option-parsing-changes.patch
Patch223: libvirt-util-Fix-crash-when-removing-entries-during-hash-iteration.patch
Patch224: libvirt-tests-Unit-tests-for-internal-hash-APIs.patch
Patch225: libvirt-Experimental-libvirtd-upstart-job.patch

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
URL: http://libvirt.org/
BuildRequires: python-devel
BuildRequires: autoconf automake libtool

# The client side, i.e. shared libs and virsh are in a subpackage
Requires: %{name}-client = %{version}-%{release}

# Used by many of the drivers, so turn it on whenever the
# daemon is present
%if %{with_libvirtd}
Requires: bridge-utils
# for modprobe of pci devices
Requires: module-init-tools
# for /sbin/ip
Requires: iproute
%endif
%if %{with_network}
Requires: dnsmasq >= 2.41
Requires: radvd
%endif
%if %{with_network} || %{with_nwfilter}
Requires: iptables
Requires: iptables-ipv6
%endif
%if %{with_nwfilter}
Requires: ebtables
%endif
# needed for device enumeration
%if %{with_hal}
Requires: hal
%endif
%if %{with_udev}
Requires: udev >= 145
%endif
%if %{with_polkit}
%if 0%{?fedora} >= 12 || 0%{?rhel} >=6
Requires: polkit >= 0.93
%else
Requires: PolicyKit >= 0.6
%endif
%endif
%if %{with_storage_fs}
# For mount/umount in FS driver
BuildRequires: util-linux
# For showmount in FS driver (netfs discovery)
BuildRequires: nfs-utils
Requires: nfs-utils
# For glusterfs
%if 0%{?fedora} >= 11
Requires: glusterfs-client >= 2.0.1
%endif
%endif
%if %{with_qemu}
# From QEMU RPMs
Requires: /usr/bin/qemu-img
# For image compression
Requires: gzip
Requires: bzip2
Requires: lzop
Requires: xz
%else
%if %{with_xen}
# From Xen RPMs
Requires: /usr/sbin/qcow-create
%endif
%endif
%if %{with_storage_lvm}
# For LVM drivers
Requires: lvm2
%endif
%if %{with_storage_iscsi}
# For ISCSI driver
Requires: iscsi-initiator-utils
%endif
%if %{with_storage_disk}
# For disk driver
Requires: parted
%endif
%if %{with_storage_mpath}
# For multipath support
Requires: device-mapper
%endif
%if %{with_cgconfig}
Requires: libcgroup
%endif
%if %{with_xen}
BuildRequires: xen-devel
%endif
%if %{with_one}
BuildRequires: xmlrpc-c-devel >= 1.14.0
%endif
BuildRequires: libxml2-devel
BuildRequires: xhtml1-dtds
BuildRequires: libxslt
BuildRequires: readline-devel
BuildRequires: ncurses-devel
BuildRequires: gettext
BuildRequires: gnutls-devel
%if 0%{?fedora} >= 12 || 0%{?rhel} >= 6
# for augparse, optionally used in testing
BuildRequires: augeas
%endif
%if %{with_hal}
BuildRequires: hal-devel
%endif
%if %{with_udev}
BuildRequires: libudev-devel >= 145
BuildRequires: libpciaccess-devel >= 0.10.9
%endif
%if %{with_yajl}
BuildRequires: yajl-devel
%endif
%if %{with_libpcap}
BuildRequires: libpcap-devel
%endif
%if %{with_libnl}
BuildRequires: libnl-devel
%endif
%if %{with_avahi}
BuildRequires: avahi-devel
%endif
%if %{with_selinux}
BuildRequires: libselinux-devel
%endif
%if %{with_network}
BuildRequires: dnsmasq >= 2.41
BuildRequires: iptables
BuildRequires: iptables-ipv6
BuildRequires: radvd
%endif
%if %{with_nwfilter}
BuildRequires: ebtables
%endif
BuildRequires: bridge-utils
BuildRequires: module-init-tools
%if %{with_sasl}
BuildRequires: cyrus-sasl-devel
%endif
%if %{with_polkit}
%if 0%{?fedora} >= 12 || 0%{?rhel} >= 6
# Only need the binary, not -devel
BuildRequires: polkit >= 0.93
%else
BuildRequires: PolicyKit-devel >= 0.6
%endif
%endif
%if %{with_storage_fs}
# For mount/umount in FS driver
BuildRequires: util-linux
%endif
%if %{with_qemu}
# From QEMU RPMs
BuildRequires: /usr/bin/qemu-img
%else
%if %{with_xen}
# From Xen RPMs
BuildRequires: /usr/sbin/qcow-create
%endif
%endif
%if %{with_storage_lvm}
# For LVM drivers
BuildRequires: lvm2
%endif
%if %{with_storage_iscsi}
# For ISCSI driver
BuildRequires: iscsi-initiator-utils
%endif
%if %{with_storage_disk}
# For disk driver
BuildRequires: parted-devel
%if 0%{?rhel} == 5
# Broken RHEL-5 parted RPM is missing a dep
BuildRequires: e2fsprogs-devel
%endif
%endif
%if %{with_storage_mpath}
# For Multipath support
%if 0%{?rhel} == 5
# Broken RHEL-5 packaging has header files in main RPM :-(
BuildRequires: device-mapper
%else
BuildRequires: device-mapper-devel
%endif
%endif
%if %{with_numactl}
# For QEMU/LXC numa info
BuildRequires: numactl-devel
%endif
%if %{with_capng}
BuildRequires: libcap-ng-devel >= 0.5.0
%endif
%if %{with_phyp}
BuildRequires: libssh2-devel
%endif
%if %{with_netcf}
BuildRequires: netcf-devel >= 0.1.4
%endif
%if %{with_esx}
%if 0%{?fedora} >= 9 || 0%{?rhel} >= 6
BuildRequires: libcurl-devel
%else
BuildRequires: curl-devel
%endif
%endif
%if %{with_audit}
BuildRequires: audit-libs-devel
%endif
%if %{with_dtrace}
# we need /usr/sbin/dtrace
BuildRequires: systemtap-sdt-devel
%endif


# Fedora build root suckage
BuildRequires: gawk

%description
Libvirt is a C toolkit to interact with the virtualization capabilities
of recent versions of Linux (and other OSes). The main package includes
the libvirtd server exporting the virtualization support.

%package client
Summary: Client side library and utilities of the libvirt library
Group: Development/Libraries
Requires: readline
Requires: ncurses
# So remote clients can access libvirt over SSH tunnel
# (client invokes 'nc' against the UNIX socket on the server)
Requires: nc
# Needed by virt-pki-validate script.
Requires: gnutls-utils
%if %{with_sasl}
Requires: cyrus-sasl
# Not technically required, but makes 'out-of-box' config
# work correctly & doesn't have onerous dependencies
Requires: cyrus-sasl-md5
%endif

%description client
Shared libraries and client binaries needed to access to the
virtualization capabilities of recent versions of Linux (and other OSes).

%package devel
Summary: Libraries, includes, etc. to compile with the libvirt library
Group: Development/Libraries
Requires: %{name}-client = %{version}-%{release}
Requires: pkgconfig
%if %{with_xen}
Requires: xen-devel
%endif

%description devel
Includes and documentations for the C library providing an API to use
the virtualization capabilities of recent versions of Linux (and other OSes).

%if %{with_python}
%package python
Summary: Python bindings for the libvirt library
Group: Development/Libraries
Requires: %{name}-client = %{version}-%{release}

%description python
The libvirt-python package contains a module that permits applications
written in the Python programming language to use the interface
supplied by the libvirt library to use the virtualization capabilities
of recent versions of Linux (and other OSes).
%endif

%prep
%setup -q
%patch1 -p1
%patch3 -p1
%patch4 -p1
%patch5 -p1
%patch6 -p1
%patch7 -p1
%patch9 -p1
%patch10 -p1
%patch11 -p1
%patch12 -p1
%patch13 -p1
%patch14 -p1
%patch15 -p1
%patch16 -p1
%patch17 -p1
%patch18 -p1
%patch19 -p1
%patch20 -p1
%patch21 -p1
%patch22 -p1
%patch23 -p1
%patch24 -p1
%patch25 -p1
%patch26 -p1
%patch27 -p1
%patch28 -p1
%patch29 -p1
%patch30 -p1
%patch31 -p1
%patch32 -p1
%patch33 -p1
%patch34 -p1
%patch35 -p1
%patch36 -p1
%patch37 -p1
%patch38 -p1
%patch39 -p1
%patch40 -p1
%patch41 -p1
%patch42 -p1
%patch43 -p1
%patch44 -p1
%patch45 -p1
%patch46 -p1
%patch47 -p1
%patch48 -p1
%patch49 -p1
%patch50 -p1
%patch51 -p1
%patch52 -p1
%patch53 -p1
%patch54 -p1
%patch55 -p1
%patch56 -p1
%patch57 -p1
%patch58 -p1
%patch59 -p1
%patch60 -p1
%patch61 -p1
%patch62 -p1
%patch63 -p1
%patch64 -p1
%patch65 -p1
%patch66 -p1
%patch67 -p1
%patch68 -p1
%patch69 -p1
%patch70 -p1
%patch71 -p1
%patch72 -p1
%patch73 -p1
%patch74 -p1
%patch75 -p1
%patch76 -p1
%patch77 -p1
%patch78 -p1
%patch79 -p1
%patch80 -p1
%patch81 -p1
%patch82 -p1
%patch83 -p1
%patch84 -p1
%patch85 -p1
%patch86 -p1
%patch87 -p1
%patch88 -p1
%patch89 -p1
%patch90 -p1
%patch91 -p1
%patch92 -p1
%patch93 -p1
%patch94 -p1
%patch95 -p1
%patch96 -p1
%patch97 -p1
%patch98 -p1
%patch99 -p1
%patch100 -p1
%patch101 -p1
%patch102 -p1
%patch103 -p1
%patch104 -p1
%patch105 -p1
%patch106 -p1
%patch107 -p1
%patch108 -p1
%patch109 -p1
%patch110 -p1
%patch111 -p1
%patch112 -p1
%patch113 -p1
%patch114 -p1
%patch115 -p1
%patch116 -p1
%patch117 -p1
%patch118 -p1
%patch119 -p1
%patch120 -p1
%patch121 -p1
%patch122 -p1
%patch123 -p1
%patch124 -p1
%patch125 -p1
%patch126 -p1
%patch127 -p1
%patch128 -p1
%patch129 -p1
%patch130 -p1
%patch131 -p1
%patch132 -p1
%patch133 -p1
%patch134 -p1
%patch135 -p1
%patch136 -p1
%patch137 -p1
%patch138 -p1
%patch139 -p1
%patch140 -p1
%patch141 -p1
%patch142 -p1
%patch143 -p1
%patch144 -p1
%patch145 -p1
%patch146 -p1
%patch147 -p1
%patch148 -p1
%patch149 -p1
%patch150 -p1
%patch151 -p1
%patch152 -p1
%patch153 -p1
%patch154 -p1
%patch155 -p1
%patch156 -p1
%patch157 -p1
%patch158 -p1
%patch159 -p1
%patch160 -p1
%patch161 -p1
%patch162 -p1
%patch163 -p1
%patch164 -p1
%patch165 -p1
%patch166 -p1
%patch167 -p1
%patch168 -p1
%patch169 -p1
%patch170 -p1
%patch171 -p1
%patch172 -p1
%patch173 -p1
%patch174 -p1
%patch175 -p1
%patch176 -p1
%patch177 -p1
%patch178 -p1
%patch179 -p1
%patch180 -p1
%patch181 -p1
%patch182 -p1
%patch183 -p1
%patch184 -p1
%patch185 -p1
%patch186 -p1
%patch187 -p1
%patch188 -p1
%patch189 -p1
%patch190 -p1
%patch191 -p1
%patch192 -p1
%patch193 -p1
%patch194 -p1
%patch195 -p1
%patch196 -p1
%patch197 -p1
%patch198 -p1
%patch199 -p1
%patch200 -p1
%patch201 -p1
%patch202 -p1
%patch203 -p1
%patch204 -p1
%patch205 -p1
%patch206 -p1
%patch207 -p1
%patch208 -p1
%patch209 -p1
%patch210 -p1
%patch211 -p1
%patch212 -p1
%patch213 -p1
%patch214 -p1
%patch215 -p1
%patch216 -p1
%patch217 -p1
%patch218 -p1
%patch219 -p1
%patch220 -p1
%patch221 -p1
%patch222 -p1
%patch223 -p1
%patch224 -p1
%patch225 -p1

chmod 0755 tests/virsh-optparse

%build
%if ! %{with_xen}
%define _without_xen --without-xen
%endif

%if ! %{with_qemu}
%define _without_qemu --without-qemu
%endif

%if ! %{with_openvz}
%define _without_openvz --without-openvz
%endif

%if ! %{with_lxc}
%define _without_lxc --without-lxc
%endif

%if ! %{with_vbox}
%define _without_vbox --without-vbox
%endif

%if ! %{with_xenapi}
%define _without_xenapi --without-xenapi
%endif

%if ! %{with_sasl}
%define _without_sasl --without-sasl
%endif

%if ! %{with_avahi}
%define _without_avahi --without-avahi
%endif

%if ! %{with_phyp}
%define _without_phyp --without-phyp
%endif

%if ! %{with_esx}
%define _without_esx --without-esx
%endif

%if ! %{with_vmware}
%define _without_vmware --without-vmware
%endif

%if ! %{with_polkit}
%define _without_polkit --without-polkit
%endif

%if ! %{with_python}
%define _without_python --without-python
%endif

%if ! %{with_libvirtd}
%define _without_libvirtd --without-libvirtd
%endif

%if ! %{with_uml}
%define _without_uml --without-uml
%endif

%if ! %{with_one}
%define _without_one --without-one
%endif

%if %{with_rhel5}
%define _with_rhel5_api --with-rhel5-api
%endif

%if ! %{with_network}
%define _without_network --without-network
%endif

%if ! %{with_storage_fs}
%define _without_storage_fs --without-storage-fs
%endif

%if ! %{with_storage_lvm}
%define _without_storage_lvm --without-storage-lvm
%endif

%if ! %{with_storage_iscsi}
%define _without_storage_iscsi --without-storage-iscsi
%endif

%if ! %{with_storage_disk}
%define _without_storage_disk --without-storage-disk
%endif

%if ! %{with_storage_mpath}
%define _without_storage_mpath --without-storage-mpath
%endif

%if ! %{with_numactl}
%define _without_numactl --without-numactl
%endif

%if ! %{with_capng}
%define _without_capng --without-capng
%endif

%if ! %{with_netcf}
%define _without_netcf --without-netcf
%endif

%if ! %{with_selinux}
%define _without_selinux --without-selinux
%endif

%if ! %{with_hal}
%define _without_hal --without-hal
%endif

%if ! %{with_udev}
%define _without_udev --without-udev
%endif

%if ! %{with_yajl}
%define _without_yajl --without-yajl
%endif

%if ! %{with_libpcap}
%define _without_libpcap --without-libpcap
%endif

%if ! %{with_macvtap}
%define _without_macvtap --without-macvtap
%endif

%if ! %{with_audit}
%define _without_audit --without-audit
%endif

%if ! %{with_dtrace}
%define _without_dtrace --without-dtrace
%endif

%define when  %(date +"%%F-%%T")
%define where %(hostname)
%define who   %{?packager}%{!?packager:Unknown}
%define with_packager --with-packager="%{who}, %{when}, %{where}"
%define with_packager_version --with-packager-version="%{release}"


autoreconf -if
%configure %{?_without_xen} \
           %{?_without_qemu} \
           %{?_without_openvz} \
           %{?_without_lxc} \
           %{?_without_vbox} \
           %{?_without_xenapi} \
           %{?_without_sasl} \
           %{?_without_avahi} \
           %{?_without_polkit} \
           %{?_without_python} \
           %{?_without_libvirtd} \
           %{?_without_uml} \
           %{?_without_one} \
           %{?_without_phyp} \
           %{?_without_esx} \
           %{?_without_vmware} \
           %{?_without_network} \
           %{?_with_rhel5_api} \
           %{?_without_storage_fs} \
           %{?_without_storage_lvm} \
           %{?_without_storage_iscsi} \
           %{?_without_storage_disk} \
           %{?_without_storage_mpath} \
           %{?_without_numactl} \
           %{?_without_capng} \
           %{?_without_netcf} \
           %{?_without_selinux} \
           %{?_without_hal} \
           %{?_without_udev} \
           %{?_without_yajl} \
           %{?_without_libpcap} \
           %{?_without_macvtap} \
           %{?_without_audit} \
           %{?_without_dtrace} \
           %{with_packager} \
           %{with_packager_version} \
           --with-qemu-user=%{qemu_user} \
           --with-qemu-group=%{qemu_group} \
           --with-init-script=redhat \
           --with-remote-pid-file=%{_localstatedir}/run/libvirtd.pid
make %{?_smp_mflags}
gzip -9 ChangeLog

%install
rm -fr %{buildroot}

%makeinstall
for i in domain-events/events-c dominfo domsuspend hellolibvirt openauth python xml/nwfilter systemtap
do
  (cd examples/$i ; make clean ; rm -rf .deps .libs Makefile Makefile.in)
done
rm -f $RPM_BUILD_ROOT%{_libdir}/*.la
rm -f $RPM_BUILD_ROOT%{_libdir}/*.a
rm -f $RPM_BUILD_ROOT%{_libdir}/python*/site-packages/*.la
rm -f $RPM_BUILD_ROOT%{_libdir}/python*/site-packages/*.a

%if %{with_network}
install -d -m 0755 $RPM_BUILD_ROOT%{_datadir}/lib/libvirt/dnsmasq/
# We don't want to install /etc/libvirt/qemu/networks in the main %files list
# because if the admin wants to delete the default network completely, we don't
# want to end up re-incarnating it on every RPM upgrade.
install -d -m 0755 $RPM_BUILD_ROOT%{_datadir}/libvirt/networks/
cp $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/qemu/networks/default.xml \
   $RPM_BUILD_ROOT%{_datadir}/libvirt/networks/default.xml
rm -f $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/qemu/networks/default.xml
rm -f $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/qemu/networks/autostart/default.xml
# Strip auto-generated UUID - we need it generated per-install
sed -i -e "/<uuid>/d" $RPM_BUILD_ROOT%{_datadir}/libvirt/networks/default.xml
%else
rm -f $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/qemu/networks/default.xml
rm -f $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/qemu/networks/autostart/default.xml
%endif
%if ! %{with_qemu}
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/libvirtd_qemu.aug
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/tests/test_libvirtd_qemu.aug
%endif
%find_lang %{name}

%if ! %{with_lxc}
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/libvirtd_lxc.aug
rm -f $RPM_BUILD_ROOT%{_datadir}/augeas/lenses/tests/test_libvirtd_lxc.aug
%endif

%if ! %{with_python}
rm -rf $RPM_BUILD_ROOT%{_datadir}/doc/libvirt-python-%{version}
%endif

%if %{client_only}
rm -rf $RPM_BUILD_ROOT%{_datadir}/doc/libvirt-%{version}
%endif

%if ! %{with_libvirtd}
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/nwfilter
mv $RPM_BUILD_ROOT%{_datadir}/doc/libvirt-%{version}/html \
   $RPM_BUILD_ROOT%{_datadir}/doc/libvirt-devel-%{version}/
%endif

%if ! %{with_qemu}
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/qemu.conf
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/libvirtd.qemu
%endif
%if ! %{with_lxc}
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/libvirt/lxc.conf
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/libvirtd.lxc
%endif
%if ! %{with_uml}
rm -rf $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/libvirtd.uml
%endif

%clean
rm -fr %{buildroot}

%check
cd tests
# The following test doesn't currently work in a mock build root
for i in daemon-conf
do
  rm -f $i
  printf "#!/bin/sh\nexit 0\n" > $i
  chmod +x $i
done
make check

%pre
%if 0%{?fedora} >= 12 || 0%{?rhel} >= 6
# Normally 'setup' adds this in /etc/passwd, but this is
# here for case of upgrades from earlier Fedora/RHEL. This
# UID/GID pair is reserved for qemu:qemu
getent group kvm >/dev/null || groupadd -g 36 -r kvm
getent group qemu >/dev/null || groupadd -g 107 -r qemu
getent passwd qemu >/dev/null || \
  useradd -r -u 107 -g qemu -G kvm -d / -s /sbin/nologin \
    -c "qemu user" qemu
%endif

%post

%if %{with_libvirtd}
%if %{with_network}
# We want to install the default network for initial RPM installs
# or on the first upgrade from a non-network aware libvirt only.
# We check this by looking to see if the daemon is already installed
/sbin/chkconfig --list libvirtd 1>/dev/null 2>&1
if test $? != 0 && test ! -f %{_sysconfdir}/libvirt/qemu/networks/default.xml
then
    UUID=`/usr/bin/uuidgen`
    sed -e "s,</name>,</name>\n  <uuid>$UUID</uuid>," \
         < %{_datadir}/libvirt/networks/default.xml \
         > %{_sysconfdir}/libvirt/qemu/networks/default.xml
    ln -s ../default.xml %{_sysconfdir}/libvirt/qemu/networks/autostart/default.xml
fi

# All newly defined networks will have a mac address for the bridge
# auto-generated, but networks already existing at the time of upgrade
# will not. We need to go through all the network configs, look for
# those that don't have a mac address, and add one.

network_files=$( (cd %{_localstatedir}/lib/libvirt/network && \
                  grep -L "mac address" *.xml; \
                  cd %{_sysconfdir}/libvirt/qemu/networks && \
                  grep -L "mac address" *.xml) 2>/dev/null \
                | sort -u)

for file in $network_files
do
   # each file exists in either the config or state directory (or both) and
   # does not have a mac address specified in either. We add the same mac
   # address to both files (or just one, if the other isn't there)

   mac4=`printf '%X' $(($RANDOM % 256))`
   mac5=`printf '%X' $(($RANDOM % 256))`
   mac6=`printf '%X' $(($RANDOM % 256))`
   for dir in %{_localstatedir}/lib/libvirt/network \
              %{_sysconfdir}/libvirt/qemu/networks
   do
      if test -f $dir/$file
      then
         sed -i.orig -e \
           "s|\(<bridge.*$\)|\0\n  <mac address='52:54:00:$mac4:$mac5:$mac6'/>|" \
           $dir/$file
         if test $? != 0
         then
             echo "failed to add <mac address='52:54:00:$mac4:$mac5:$mac6'/>" \
                  "to $dir/$file"
             mv -f $dir/$file.orig $dir/$file
         else
             rm -f $dir/$file.orig
         fi
      fi
   done
done
%endif

%if %{with_cgconfig}
if [ "$1" -eq "1" ]; then
/sbin/chkconfig cgconfig on
fi
%endif

/sbin/chkconfig --add libvirtd
if [ "$1" -ge "1" ]; then
	/sbin/service libvirtd condrestart > /dev/null 2>&1
fi
%endif

%preun
%if %{with_libvirtd}
if [ $1 = 0 ]; then
    /sbin/service libvirtd stop 1>/dev/null 2>&1
    /sbin/chkconfig --del libvirtd
fi
%endif

%preun client

if [ $1 = 0 ]; then
    /sbin/chkconfig --del libvirt-guests
    rm -f /var/lib/libvirt/libvirt-guests
fi

%post client

/sbin/ldconfig
/sbin/chkconfig --add libvirt-guests
if [ $1 -ge 1 ]; then
    if /sbin/chkconfig --list libvirt-guests | /bin/grep -q :on ; then
        # this doesn't do anything but allowing for libvirt-guests to be
        # stopped on the first shutdown
        /sbin/service libvirt-guests start > /dev/null 2>&1 || true
    fi
fi

%postun client -p /sbin/ldconfig

%if %{with_libvirtd}
%files
%defattr(-, root, root)

%doc AUTHORS ChangeLog.gz NEWS README COPYING.LIB TODO
%dir %attr(0700, root, root) %{_sysconfdir}/libvirt/

%if %{with_network}
%dir %attr(0700, root, root) %{_sysconfdir}/libvirt/qemu/
%dir %attr(0700, root, root) %{_sysconfdir}/libvirt/qemu/networks/
%dir %attr(0700, root, root) %{_sysconfdir}/libvirt/qemu/networks/autostart
%endif

%dir %attr(0700, root, root) %{_sysconfdir}/libvirt/nwfilter/
%{_sysconfdir}/libvirt/nwfilter/*.xml

%{_sysconfdir}/rc.d/init.d/libvirtd
%doc daemon/libvirtd.upstart
%config(noreplace) %{_sysconfdir}/sysconfig/libvirtd
%config(noreplace) %{_sysconfdir}/libvirt/libvirtd.conf
%if %{with_dtrace}
%{_datadir}/systemtap/tapset/libvirtd.stp
%endif
%dir %attr(0700, root, root) %{_localstatedir}/log/libvirt/qemu/
%dir %attr(0700, root, root) %{_localstatedir}/log/libvirt/lxc/
%dir %attr(0700, root, root) %{_localstatedir}/log/libvirt/uml/

%if %{with_qemu}
%config(noreplace) %{_sysconfdir}/libvirt/qemu.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/libvirtd.qemu
%endif
%if %{with_lxc}
%config(noreplace) %{_sysconfdir}/libvirt/lxc.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/libvirtd.lxc
%endif
%if %{with_uml}
%config(noreplace) %{_sysconfdir}/logrotate.d/libvirtd.uml
%endif

%dir %{_datadir}/libvirt/

%if %{with_network}
%dir %{_datadir}/libvirt/networks/
%{_datadir}/libvirt/networks/default.xml
%endif

%dir %{_localstatedir}/run/libvirt/

%dir %attr(0711, root, root) %{_localstatedir}/lib/libvirt/images/
%dir %attr(0711, root, root) %{_localstatedir}/lib/libvirt/boot/
%dir %attr(0700, root, root) %{_localstatedir}/cache/libvirt/

%if %{with_qemu}
%dir %attr(0700, root, root) %{_localstatedir}/run/libvirt/qemu/
%dir %attr(0750, %{qemu_user}, %{qemu_group}) %{_localstatedir}/lib/libvirt/qemu/
%dir %attr(0750, %{qemu_user}, %{qemu_group}) %{_localstatedir}/cache/libvirt/qemu/
%endif
%if %{with_lxc}
%dir %{_localstatedir}/run/libvirt/lxc/
%dir %attr(0700, root, root) %{_localstatedir}/lib/libvirt/lxc/
%endif
%if %{with_uml}
%dir %{_localstatedir}/run/libvirt/uml/
%dir %attr(0700, root, root) %{_localstatedir}/lib/libvirt/uml/
%endif
%if %{with_network}
%dir %{_localstatedir}/run/libvirt/network/
%dir %attr(0700, root, root) %{_localstatedir}/lib/libvirt/network/
%dir %attr(0755, root, root) %{_localstatedir}/lib/libvirt/dnsmasq/
%endif

%if %{with_qemu}
%{_datadir}/augeas/lenses/libvirtd_qemu.aug
%{_datadir}/augeas/lenses/tests/test_libvirtd_qemu.aug
%endif

%if %{with_lxc}
%{_datadir}/augeas/lenses/libvirtd_lxc.aug
%{_datadir}/augeas/lenses/tests/test_libvirtd_lxc.aug
%endif

%{_datadir}/augeas/lenses/libvirtd.aug
%{_datadir}/augeas/lenses/tests/test_libvirtd.aug

%if %{with_polkit}
%if 0%{?fedora} >= 12 || 0%{?rhel} >= 6
%{_datadir}/polkit-1/actions/org.libvirt.unix.policy
%else
%{_datadir}/PolicyKit/policy/org.libvirt.unix.policy
%endif
%endif

%dir %attr(0700, root, root) %{_localstatedir}/log/libvirt/

%if %{with_lxc}
%attr(0755, root, root) %{_libexecdir}/libvirt_lxc
%endif

%attr(0755, root, root) %{_libexecdir}/libvirt_parthelper
%attr(0755, root, root) %{_sbindir}/libvirtd

%{_mandir}/man8/libvirtd.8*

%doc docs/*.xml
%endif

%files client -f %{name}.lang
%defattr(-, root, root)
%doc AUTHORS ChangeLog.gz NEWS README COPYING.LIB TODO

%{_mandir}/man1/virsh.1*
%{_mandir}/man1/virt-xml-validate.1*
%{_mandir}/man1/virt-pki-validate.1*
%{_bindir}/virsh
%{_bindir}/virt-xml-validate
%{_bindir}/virt-pki-validate
%{_libdir}/lib*.so.*

%dir %{_datadir}/libvirt/
%dir %{_datadir}/libvirt/schemas/

%{_datadir}/libvirt/schemas/domain.rng
%{_datadir}/libvirt/schemas/domainsnapshot.rng
%{_datadir}/libvirt/schemas/network.rng
%{_datadir}/libvirt/schemas/storagepool.rng
%{_datadir}/libvirt/schemas/storagevol.rng
%{_datadir}/libvirt/schemas/nodedev.rng
%{_datadir}/libvirt/schemas/capability.rng
%{_datadir}/libvirt/schemas/interface.rng
%{_datadir}/libvirt/schemas/secret.rng
%{_datadir}/libvirt/schemas/storageencryption.rng
%{_datadir}/libvirt/schemas/nwfilter.rng

%{_datadir}/libvirt/cpu_map.xml

%{_sysconfdir}/rc.d/init.d/libvirt-guests
%config(noreplace) %{_sysconfdir}/sysconfig/libvirt-guests
%dir %attr(0755, root, root) %{_localstatedir}/lib/libvirt/

%if %{with_sasl}
%config(noreplace) %{_sysconfdir}/sasl2/libvirt.conf
%endif

%files devel
%defattr(-, root, root)

%{_libdir}/lib*.so
%dir %{_includedir}/libvirt
%{_includedir}/libvirt/*.h
%{_libdir}/pkgconfig/libvirt.pc
%dir %{_datadir}/gtk-doc/html/libvirt/
%doc %{_datadir}/gtk-doc/html/libvirt/*.devhelp
%doc %{_datadir}/gtk-doc/html/libvirt/*.html
%doc %{_datadir}/gtk-doc/html/libvirt/*.png
%doc %{_datadir}/gtk-doc/html/libvirt/*.css

%doc docs/*.html docs/html docs/*.gif
%doc docs/libvirt-api.xml
%doc examples/hellolibvirt
%doc examples/domain-events/events-c
%doc examples/dominfo
%doc examples/domsuspend
%doc examples/openauth
%doc examples/xml
%doc examples/systemtap

%if %{with_python}
%files python
%defattr(-, root, root)

%doc AUTHORS NEWS README COPYING.LIB
%{_libdir}/python*/site-packages/libvirt.py*
%{_libdir}/python*/site-packages/libvirtmod*
%doc python/tests/*.py
%doc python/TODO
%doc examples/python
%doc examples/domain-events/events-python
%endif

%changelog
* Mon Apr 18 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.7-18.el6
- network: Fix NULL dereference during error recovery (rhbz#696660)
- virsh: Fix regression in parsing optional integer (rhbz#693963)
- util: Fix crash when removing entries during hash iteration (rhbz#693385)
- Experimental libvirtd upstart job (rhbz#678084)

* Wed Apr 13 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.7-17.el6
- Don't return an error on failure to create blkio controller (rhbz#689030)
- Fix possible infinite loop in remote driver (rhbz#691514)
- qemu: Remove the managed state file only if restoring succeeded (rhbz#692998)
- docs: Tweak virsh restore warning (rhbz#692998)

* Wed Apr  6 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.7-16.el6
- nwfilter: Enable rejection of packets (rhbz#681948)
- Revert all previous error log priority hacks (rhbz#587603)
- Filter out certain expected error messages from libvirtd (rhbz#587603)
- qemu: Unlock qemu driver before return from domain save (rhbz#688774)
- Do not send monitor command after monitor meet error (rhbz#688774)
- qemu: Ignore libvirt debug messages in qemu log (rhbz#681492)
- virsh: Fix memtune's help message for swap_hard_limit (rhbz#680190)
- virsh: Fix documentation for memtune command (rhbz#680190)
- docs: Fix typo (rhbz#680190)
- Fix typo in systemtap tapset directory name (rhbz#693701)
- qemu: Ignore unusable binaries (rhbz#676563)
- qemu: Support for overriding NPROC limit (rhbz#674602)

* Tue Mar 29 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.7-15.el6
- Fix return value for virJSONValueFromString if it fails (rhbz#688723)
- Fix positioning to end of qemu log file (rhbz#689986)
- Initialization error of qemuCgroupData in Qemu host usb hotplug (rhbz#690183)
- 8021Qbh: Use preassociate-rr during the migration prepare stage (rhbz#684870)
- Make error reporting in libvirtd thread safe (rhbz#689374)
- Add missing dependencies (rhbz#690022)
- Fix restoring a compressed save image (rhbz#691034)
- Fix label restore bugs in qemu driver (rhbz#690737)

* Tue Mar 22 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.7-14.el6
- Fix delayed events when SASL is active (rhbz#624252)
- Fix ref-counting bugs (rhbz#688774)
- Log an error if on failure to connect to netlink socket (rhbz#689001)
- Log error and abort network startup when radvd isn't found (rhbz#688957)
- Add PCI sysfs reset access rights to qemu (rhbz#689002)
- Fix regression with qemu:///session URI (rhbz#684655)
- Avoid leaking PCI config fd into qemu (rhbz#687993)

* Wed Mar 16 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.7-13.el6
- Properly report error in virConnectDomainXMLToNative (CVE-2011-1146)
- Handle DNS over IPv6 (rhbz#687896)
- Start dnsmasq even if no dhcp ranges/hosts are specified (rhbz#687291)
- Use a separate dhcp leases file for each network (rhbz#687551)
- Fix a possible crash in storage driver (rhbz#684712)

* Tue Mar 15 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.7-12.el6
- Fix vram settings for qxl graphics (rhbz#673578)
- Free stream when domain shuts down while its console is open (rhbz#682741)
- Use hardcoded python path in libvirt.py (rhbz#684204)
- Add missing checks for read only connections (CVE-2011-1146)
- Eliminate potential null pointer deref when auditing macvtap devices (rhbz#642785)
- Insert error messages to avoid a quiet abortion of commands (rhbz#605660)

* Thu Mar 10 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.7-11.el6
- Support vram specification for qxl graphics (rhbz#673578)
- Fix parsing int options in virsh (rhbz#639587)
- Use -o encryption=on instead of -e for qemu-img (rhbz#676984)
- Support domain snapshots with current QMP (rhbz#589076)
- Update auditing support (rhbz#642785)
- Only request sound cgroup ACL when required (rhbz#680398)
- Allow fine-tuning of device ACL permissions (rhbz#683163)
- Support vhost in attach-interface (rhbz#683276)
- Don't request cgroup ACL access for /dev/net/tun (rhbz#683305)

* Mon Mar 07 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.7-10.el6
- Fix deadlock caused by a fix for rhbz#670848

* Fri Mar 04 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.7-9.el6
- Reorder nwfilter match extensions relative to state match (rhbz#678139)
- Avoid overwriting error message in qemu driver (rhbz#678870)
- Allow removing hash entries in virHashForEach (rhbz#681459)
- Avoid double close on qemu domain restore (rhbz#672725)
- Fix DomainObj refcounting/hashtable races in qemu driver (rhbz#670848)
- Fix several memory leaks (rhbz#682249)

* Thu Feb 24 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.7-8.el6
- Fix --all flag of virsh freecell to really show all cells (rhbz#653530)
- Add txmode attribute to interface XML for virtio backend (rhbz#629662)
- Give each virtual network bridge its own fixed MAC address (rhbz#609463)
- Fix virsh snapshot-list with --quiet option (rhbz#678833)
- Delay IFF_UP'ing 802.1Qbh interface until migration final stage (rhbz#678826)
- Fix several memory bugs (rhbz#679164)
- Fix virt-pki-validate when CERTTOOL is missing (rhbz#679153)
- Fix memory corruption in virFileAbsPath (rhbz#680281)

* Thu Feb 17 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.7-7.el6
- Properly escape special characters in domain names (rhbz#676908)
- Fix enum type declaration (rhbz#628940)
- Fix cleanup on VM state after failed QEMU startup (rhbz#673588)
- Fix XML generation for smartcards (rhbz#677308)
- Ignore failure of "qemu -M ?" on older qemu (rhbz#676563)
- Fix typo in setting up SPICE passwords (rhbz#677709)
- Avoid NULL dereference in virDomainMemoryStats (rhbz#677484)
- Avoid NULL dereference on error in qemu driver (rhbz#677493)
- Fix error message when saving a shutoff domain (rhbz#677547)
- Create enough volumes for mpath pool (rhbz#677231)
- Allow to delete device mapper disk partition (rhbz#611443)

* Fri Feb 11 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.7-6.el6
- Fix typo in parsing of spice 'auth' data (rhbz#676374)
- Fix attach-interface regression (rhbz#676686)
- Block I/O tunables via blkio cgroups controller (rhbz#632492)
- Support SCSI RAID type & lower log level for unknown types (rhbz#675771)
- Only initialize/cleanup libpciaccess once (rhbz#675698)
- Imprint all logs with version + package build information (rhbz#673226)

* Thu Feb 04 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.7-5.el6
- Docs for customizable x509 certificate paths for client (rhbz#629510)
- Fix tests for VNC over a unix domain socket (rhbz#651415)
- Fix problems with peer-to-peer migration (rhbz#673434)
- Fix tunneled migration broken since 0.8.7-2 (rhbz#672199)
- Update docs for cpu_shares setting (rhbz#641187)
- Fix possible hang if SASL is used (rhbz#672226)
- Cancel migration in progress when virsh gets Ctrl-C (rhbz#635353)
- Enhance virsh migrate command (rhbz#619039)
- Support for specifying AIO mode for qemu disks (rhbz#591703)
- Don't leave domain paused after restore (rhbz#670278)
- Fix possible deadlock/crash in qemu driver (rhbz#673588)
- Add shortcut for qemu HMP pass through (rhbz#628940)
- Fix error message when attach device fails (rhbz#675030)
- Support for booting from assigned PCI devices (rhbz#646895)
- Improve handling of unlimited value for memory tunables (rhbz#669069)
- Add smartcard support (rhbz#641834)
- Remove some RHEL-specific patches which are no longer required (rhbz#653985)
- Support for disabling/enabling KSM per domain (rhbz#635419)
- Add --all flag to virsh freecell command (rhbz#653530)

* Thu Jan 27 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.7-4.el6
- Fix event-handling data race (rhbz#671567)
- Add support for VNC over a unix domain socket (rhbz#651415)
- Support intel 'ich6' model (rhbz#648486)
- Do not use virtio-serial port 0 for generic ports (rhbz#670394)
- Set SELinux context label of pipes used for qemu migration (rhbz#667756)
- Support customizable x509 certificate paths for client (rhbz#629510)
- Round up capacity for LVM volume creation (rhbz#670529)
- Show error prompt when trying to managed save a shutoff domain (rhbz#672449)
- Report more proper error for unsupported graphics (rhbz#671319)
- Expand the man page text for virsh setmaxmem (rhbz#622534)
- Fix event-handling allocation crash (rhbz#671564)
- Require --mac to avoid detach-interface ambiguity (rhbz#671050)

* Thu Jan 20 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.7-3.el6
- Report error if invalid type specified for character device (rhbz#638968)
- Improve log for domain related APIs (rhbz#640202)
- Reject SDL graphic if it's not supported by qemu (rhbz#633326)
- Don't lose track of events when callbacks are slow (rhbz#624252)
- Fail if per-device boot is used but deviceboot is not supported (rhbz#670399)
- Avoid sending STOPPED event twice (rhbz#666158)
- Fix issues introduced by dependency patches for rhbz#646895

* Mon Jan 17 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.7-2.el6
- Fix spec file which was not fully rebased to 0.8.7 (rhbz#653985, rhbz#660706)
- Skip IB700 watchdog device when assigning PCI slots (rhbz#667091)
- Improve error reporting when parsing dhcp info (rhbz#653300)
- Don't chown saved image back to root if dynamic_ownership=0 (rhbz#661720)
- Fix core dumps if unix_sock_group is set (rhbz#623166)
- Add support for Westmere CPU model (rhbz#656248)
- Add XML config switch to enable/disable vhost-net support (rhbz#643050)
- Enable tuning of qemu network tap device "sndbuf" size (rhbz#665293)
- Support for explicit boot device ordering (rhbz#646895)
- Avoid qemu holding migration fd indefinitely (rhbz#620363)

* Sun Jan 09 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.7-1.el6
- Rebased to upstream 0.8.7 (rhbz#653985)
- The following bugs got fixed by the rebase:
    rhbz#586124, rhbz#595350, rhbz#611793, rhbz#611822, rhbz#617439,
    rhbz#620363, rhbz#626873, rhbz#627143, rhbz#628772, rhbz#639595,
    rhbz#639603, rhbz#656795, rhbz#658657, rhbz#659855, rhbz#660706,
    rhbz#664406, rhbz#665446

* Thu Dec 23 2010 Jiri Denemark <jdenemar@redhat.com> - 0.8.6-1.el6
- Rebased to upstream 0.8.6 (rhbz#653985)

* Fri Dec 10 2010 Jiri Denemark <jdenemar@redhat.com> - 0.8.1-29.el6
- spec file cleanups (rhbz#649523)
- Fix deadlock on concurrent multiple bidirectional migration (rhbz#659310)
- Fix funny error in clock-variable (rhbz#660194)
- Export host information through SMBIOS to guests (rhbz#526224)
- Ensure device is deleted from guest after unplug (rhbz#644015)
- Distinguish between QEMU domain shutdown and crash (rhbz#656845)

* Mon Nov 29 2010 Jiri Denemark <jdenemar@redhat.com> - 0.8.1-28.el6
- Fix JSON migrate_set_downtime command (rhbz#561935)
- Make SASL work over UNIX domain sockets (rhbz#641687)
- Let qemu group look below /var/lib/libvirt/qemu/ (rhbz#643407)
- Fix save/restore on root_squashed NFS (rhbz#643884)
- Fix race on multiple migration (rhbz#638285)
- Export host information through SMBIOS to guests (rhbz#526224)
- Support forcing a CDROM eject (rhbz#626305)

* Wed Aug 18 2010 Daniel Veillard <veillard@redhat.com> - 0.8.1-27
- build -26 hit a miscompilation error c.f. 624895 drop %{?_smp_mflags}
- Resolves: rhbz#620847
- Resolves: rhbz#623877

* Tue Aug 17 2010 Dave Allan <dallan@redhat.com> - 0.8.1-26
- Fix problem with capabilities XML generation
- Resolves: rhbz#620847
- Correctly reserve and release PCI slots
- Resolves: rhbz#623877

* Sun Aug 15 2010 Daniel Veillard <veillard@redhat.com> - 0.8.1-25
- fix PXE booting on the virtual network
- Resolves: rhbz#623951
- fix tunelled migration
- Resolves: rhbz#624062

* Thu Aug 12 2010 Daniel Veillard <veillard@redhat.com> - 0.8.1-24
- do not call balloon info command if balloon is desactivated
- Resolves: rhbz#617286

* Wed Aug 11 2010 Daniel Veillard <veillard@redhat.com> - 0.8.1-23
- give a way to desactivate memory balloon support
- Resolves: rhbz#617286

* Tue Aug 10 2010 Dave Allan <dallan@redhat.com> - 0.8.1-22
- Mitigate asynchronous device_del
- Resolves: rhbz#609437
- Fix PCI address allocation
- Resolves: rhbz#618484
- Make nodeinfo skip offline CPUs
- Resolves: rhbz#622515

* Tue Aug  3 2010 Dave Allan <dallan@redhat.com> - 0.8.1-21
- Fix multiple PCI device assignment bugs
- Resolves: rhbz#617116
- Fix the ACS checking in the PCI code
- Resolves: rhbz#615218
- Disable boot=on when not using KVM
- Resolves: rhbz#594068
- Don't leak delay string when freeing virInterfaceBridgeDefs
- Resolves: rhbz#620837

* Wed Jul 28 2010 Dave Allan <dallan@redhat.com> - 0.8.1-20
- Fix error message in guests init script when libvirtd isn't installed
- Resolves: rhbz#617527

* Tue Jul 27 2010 Dave Allan <dallan@redhat.com> - 0.8.1-19
- Add character device backend activating QEMU internal spice agent
- Resolves: rhbz#615757
- Make libvirt-guests initscript Fedora compliant
- Resolves: rhbz#617300

* Thu Jul 22 2010 Daniel Veillard <veillard@redhat.com> - 0.8.1-18
- Fix patch for PIIX3 slot 1 reservation, in case it's already reserved
- Resolves: rhbz#592026

* Wed Jul 21 2010 Dave Allan <dallan@redhat.com> - 0.8.1-17
- Set a stable & high MAC addr for guest TAP devices
- Resolves: rhbz#616517
- Fix bogus commit of -16 patches
- Related: rhbz#592026
- Related: rhbz#599590

* Wed Jul 21 2010 Dave Allan <dallan@redhat.com> - 0.8.1-16
- Make PCI device ordering consistent with older releases
- Resolves: rhbz#592026
- Fix libvirtd hang during concurrent bi-directional migration
- Resolves: rhbz#599590

* Wed Jul 14 2010 Dave Allan <dallan@redhat.com> - 0.8.1-15
- Add iptables rule to fixup DHCP response checksum
- Resolves: rhbz#612588

* Tue Jul 13 2010 Dave Allan <dallan@redhat.com> - 0.8.1-14
- Support virtio disk hotplug in JSON mode
- Resolves: rhbz#573946
- Fix QEMU monitor JSON crash
- Resolves: rhbz#604585
- CVE-2010-2237 CVE-2010-2238 CVE-2010-2239
- Resolves: rhbz#607817
- CVE-2010-2242 Apply a source port mapping to virtual network masquerading
- Resolves: rhbz#608049
- Fix hang if QEMU exits (almost) immediately
- Resolves: rhbz#610056
- Support new CPU models provided by qemu-kvm
- Resolves: rhbz#605830
- Fix comparison of two host CPUs
- Resolves: rhbz#611401
- Don't mess with the CPU returned by arch driver
- Resolves: rhbz#613014
- Fail when CPU type cannot be detected from XML
- Resolves: rhbz#613760
- Use -nodefconfig when probing for CPU models
- Resolves: rhbz#613764
- cpuCompare: Fix crash on unexpected CPU XML
- Resolves: rhbz#613765
- Properly report failure to create raw storage volume files
- Related: rhbz#547543
- Fix IOErrorReasonCallback python bindings
- Related: rhbz#586353
- Parthelper: canonicalize block device paths
- Related: rhbz#593785

* Wed Jun 30 2010 Dave Allan <dallan@redhat.com> - 0.8.1-13
- Don't invoke destroy callback from qemuMonitorOpen() failure paths (v2)
- Related: rhbz#609060

* Tue Jun 29 2010 Dave Allan <dallan@redhat.com> - 0.8.1-12
- Don't invoke destroy callback from qemuMonitorOpen() failure paths
- Resolves: rhbz#609060
- virFileResolveLink: guarantee an absolute path
- Resolves: rhbz#608092
- SPICE patches have translatable strings without format args
- Resolves: rhbz#608917
- No way to pass disk format type to pool-define-as nor pool-create-as
- Resolves: rhbz#597790
- Fix enforcement of direction of traffic for rules describing incoming traffic
- Resolves: rhbz#606889
- Clarify virsh help pool-create-as text
- Resolves: rhbz#609044

* Mon Jun 28 2010 Dave Allan <dallan@redhat.com> - 0.8.1-11
- Do not block during incoming migration
- Resolves: rhbz#579440
- Label serial devices
- Resolves: rhbz#585249
- parthelper: fix compilation without optimization
- Related: rhbz#593785
- Fix name/UUID uniqueness checking in storage/network
- Resolves: rhbz#593951
- Don't squash file permissions when migration fails
- Resolves: rhbz#607922
- Properly handle 'usbX' sysfs files
- Resolves: rhbz#603867
- add pool support to vol-key command & improve vol commands help
- Resolves: rhbz#598365
- document attach-disk better
- Resolves: rhbz#601143
- Config iptables to allow tftp port if network <tftp> element exists
- Resolves: rhbz#607294
- Fix failure to generate python bindings when libvirt.h.in is updated
- Related: rhbz#589465
- Allow all interface names
- Resolves: rhbz#593907
- Fix nodedevice refcounting
- Resolves: rhbz#608753
- Move nwfilter functions inside extern C and fix a locking bug
- Resolves: rhbz#597391
- Fix failure to restore qemu domains with selinux enforcing
- Resolves: rhbz#590975
- Check for presence of qemu -nodefconfig option before using it
- Resolves: rhbz#608859

* Mon Jun 21 2010 Dave Allan <dallan@redhat.com> - 0.8.1-10
- Add multiIQN XML output
- Resolves: rhbz#587700
- Fix udev node device parent-child device relationships
- Resolves: rhbz#593995
- Fix leaks in udev device add/remove
- Resolves: rhbz#595490
- Fix device destroy return value
- Resolves: rhbz#597998
- Update nodedev scsi_host data before use
- Resolves: rhbz#600048
- Display wireless devices in nodedev list
- Resolves: rhbz#604811
- Show pool and domain persistence
- Resolves: rhbz#603696
- Fix cleanup after failing to hotplug a PCI device
- Resolves: rhbz#605168
- Add '-nodefconfig' command line arg to QEMU
- Resolves: rhbz#602778
- Switch to private redhat namespace for QMP I/O error reason
- Resolves: rhbz#586353
- Improve error messages for missing drivers & unsupported functions
- Resolves: rhbz#595609
- macvtap: get interface index if not provided
- Resolves: rhbz#605187
- Fix leaks in remote code
- Resolves: rhbz#603442
- Add an optional switch --uuid to the virsh vol-pool command
- Resolves: rhbz#604929
- Change per-connection hashes to be indexed by UUIDs
- Resolves: rhbz#603494
- Run virsh from libvirt-guests script with /dev/null on stdin
- Resolves: rhbz#606314
- Increase dd block size to speed up domain save
- Resolves: rhbz#601775
- Fix reference counting bugs on qemu monitor
- Resolves: rhbz#602660
- Add missing action parameter in IO error callback
- Resolves: rhbz#607157

* Wed Jun 16 2010 Dave Allan <dallan@redhat.com> - 0.8.1-9
- Touch libvirt-guests lockfile
- Resolves: rhbz#566647
- Add qemu.conf option for clearing capabilities
- Resolves: rhbz#593903
- Add support for launching guest in paused state
- Resolves: rhbz#589465
- Add virsh vol-pool command
- Resolves: rhbz#602217
- Add vol commands to virsh man page
- Resolves: rhbz#600640
- Remove bogus migrate error messages
- Resolves: rhbz#601575


* Thu Jun 10 2010 Dave Allan <dallan@redhat.com> - 0.8.1-8
- Ensure virtio serial has stable addressing
- Resolves: rhbz#586665
- SELinux socket labelling on QEMU monitor socket for MLS
- Resolves: rhbz#593739
- Fix enumeration of partitions in disks with a trailing digit in path
- Resolves: rhbz#593785
- Enable probing of VPC disk format type
- Resolves: rhbz#597981
- Delete UNIX domain sockets upon daemon shutdown
- Resolves: rhbz#598163
- Fix Migration failure 'canonical hostname pointed to localhost'
- Resolves: rhbz#589864
- Fix up the python bindings for snapshotting
- Resolves: rhbz#591839
- Sanitize pool target paths
- Resolves: rhbz#593565
- Prevent host network conflicts
- Resolves: rhbz#594494
- Support 802.1Qbg and bh (vnlink/VEPA) (refresh)
- Resolves: rhbz#590110

* Wed May 26 2010 Dave Allan <dallan@redhat.com> - 0.8.1-7
- Fix sign extension error in libvirt's parsing of qemu options
- Resolves: rhbz#592070
- Graceful shutdown/suspend of libvirt guests on host shutdown
- Resolves: rhbz#566647
- Fix pci device hotplug
- Resolves: rhbz#572867
- Support 802.1Qbg and bh
- Resolves: rhbz#532760, rhbz#570949, rhbz#590110, rhbz#570923

* Wed May 19 2010 Dave Allan <dallan@redhat.com> - 0.8.1-6
- Support seamless migration of SPICE graphics clients (refresh)
- Resolves: rhbz#591551
- Fix swapping of PCI vendor & product names in udev backend
- Resolves: rhbz#578419
- Fix cgroup setup code to cope with root squashing NFS
- Resolves: rhbz#593193
- Fix startup error reporting race
- Resolves: rhbz#591272

* Tue May 18 2010 Dave Allan <dallan@redhat.com> - 0.8.1-5
- Don't reset user/group/security label for any files on shared filesystems
- Resolves: rhbz#578889
- Make saved state labelling ignore the dynamic_ownership parameter
- Resolves: rhbz#588562
- Fix & protect against NULL pointer dereference in monitor code
- Resolves: rhbz#591076
- Fix virFileResolveLink return value
- Resolves: rhbz#591363
- Add support for SSE4.1 and SSE4.2 CPU features
- Resolves: rhbz#592977

* Wed May 14 2010 Dave Allan <dallan@redhat.com> - 0.8.1-4
- query QEMU to get the actual allocated extent of a block device
- Resolves: rhbz#526289

* Wed May 12 2010 Daniel Veillard <veillard@redhat.com> - 0.8.1-3
- missing python bindings due to older XML api
- Resolves: rhbz#589453
- Fix two possible crashes in JSON event dispatch
- Resolves: rhbz#586353
- Fix handling of disk backing stores with cgroups
- Resolves: rhbz#581476
- virsh schedinfo --set error handling on unknow parameters
- Resolves: rhbz#586632
- Apply extra patches for nwfilter
- Resolves: rhbz#588554
- Fix hang during concurrent guest migrations
- Resolves: rhbz#582278

* Fri May  7 2010 Daniel Veillard <veillard@redhat.com> - 0.8.1-2
- Don't wipe generated iface target in active domains (588046)
- Fix LXC domain lookup and error handling (586361)
- Fix a protocol breakage introduced in libvirt-0.8.0
- Add support for nic hotplug in QEMU/KVM (589978)
- Seemless migration of spice graphics clients (589989)
- fix build with ESX support
- Resolves: rhbz#581966
- fix multilib problem (587231)

* Fri Apr 30 2010 Daniel Veillard <veillard@redhat.com> - 0.8.1-1
- Rebase to upstream 0.8.1
- Resolves: rhbz#558761

* Fri Apr 23 2010 Daniel Veillard <veillard@redhat.com> - 0.8.0-4
- Fix libvirtd startup when avahi failed to look up local host name
- CPU selection fixes
- Resolves: rhbz#581627
- fix migration poll value
- Resolves: rhbz#584928
- crash dump job caused libvirt hang
- Resolves: rhbz#580853
- Fix initial VCPU pinning in qemu driver
- Resolves: rhbz#578434
- fix cpu hotplug command names

* Tue Apr 20 2010 Daniel Veillard <veillard@redhat.com> - 0.8.0-3
- Build ESX support in
- Resolves: rhbz#581966
- a batch of network filter fixes, IBM request and upstream fixes
- Resolves: rhbz#579993
- couple of patchs to fix device handling with QMP
- Related: rhbz#563189
- fix python binding for snapshotting
- spec file fixes for nwfiler build and RHEL-5 virt-v2v specific rebuild

* Tue Apr 13 2010 Daniel P. Berrange <berrange@redhat.com> - 0.8.0-2
- Refresh SPICE patches to fix test failures
- Related: rhbz#515265, rhbz#524623, rhbz#573382
- Enable test suite during build, disabling tests that don't work in mock
- Related: rhbz#558761

* Mon Apr 12 2010 Daniel Veillard <veillard@redhat.com> - 0.8.0-1
- official 0.8.0 upstream release
- Resolves: rhbz#558761
- new patch set of patches for RHEL-6 SPICE and addons
- Enable QMP/ JSON mode in the QEMU monitor
- Resolves: rhbz#563189
- Support configuration of SPICE as a graphics protocol
- Resolves: rhbz#515265
- vnc (and spice) ticketing
- Resolves: rhbz#524623
- enable spice tls encryption in domainXML, and which channels are encrypted
- Resolves: rhbz#573382
- notification of VNC/SPICE client disconnect/connect events
- Resolves: rhbz#515268

* Wed Apr  7 2010 Daniel Veillard <veillard@redhat.com> - 0.8.0-0.pre20100407
- preview #4 for 0.8.0 rebase
- snapshot API
- domain with disk on root-squashing nfs and security driver mismatch
- Resolves: rhbz#578630
- Fail to read xml when restore domain
- Resolves: rhbz#577719
- loop "virsh cd" in virsh interactive terminal generate unknown error
- Resolves: rhbz#572380
- support setting qemu's -drive werror=stop/enospc with configuration
- Resolves: rhbz#526231

* Mon Mar 30 2010 Daniel Veillard <veillard@redhat.com> - 0.7.8-0.pre20100330
- preview #3 for 0.7.8 rebase
- kvm hpet support
- Resolves: rhbz#576973
- hook scripts support
- Resolves: rhbz#569965
- Need to add time keeping abstraction
- Resolves: rhbz#557285
- notification of guest reboot
- Resolves: rhbz#527572
- Ability to preserve RTC clock adjustments across guest reboots
- Resolves: rhbz#515273
- Notifications of guest stopping due to disk I/O errors
- Resolves: rhbz#515270
- VNC ticketing support (524623) spice still needed
- VNC client disconnect/connect events (515268) spice still needed

* Mon Mar 22 2010 Daniel Veillard <veillard@redhat.com> - 0.7.8-0.pre20100322
- preview #2 for 0.7.8 rebase
- migration max downtime API
- Resolves: rhbz#561935
- allow suspend during migration
- Resolves: rhbz#561934
- support vhost net mode at qemu startup for net devices
- Resolves: rhbz#540391
- read-only device access support for qemu
- Resolves: rhbz#556769
- LSB compliance of libvirtd init script
- Resolves: rhbz#538701
- No domain vcpu information output when using JSON monitor
- Resolves: rhbz#572051
- "qemudDomainSetMaxMemory" does not work and should be removed
- Resolves: rhbz#572146
- after setvcpus, any virsh command will be hung
- Resolves: rhbz#572193
- virsh interactive terminal crash or hung
- Resolves: rhbz#572376
- virsh hangs after core dump
- Resolves: rhbz#572544
- Fix very slow file allocation on ext3

* Fri Mar 12 2010 Daniel Veillard <veillard@redhat.com> - 0.7.8-0.pre20100312
- preview for 0.7.8 rebase
- Extra non upstream basic patch for spice and XQL
- Resolves: rhbz#515264
- Resolves: rhbz#515265
- connected virsh dies with a SIGPIPE after libvirtd restart
- Resolves: rhbz#526656
- error when running logrotate on s/390x arch
- Resolves: rhbz#547514

* Fri Mar  5 2010 Daniel Veillard <veillard@redhat.com> - 0.7.7-1
- macvtap support (rhbz#553348)
- async job handling (rhbz #515278)
- virtio channel (rhbz#515281)
- computing baseline CPU
- virDomain{Attach,Detach}DeviceFlags
- Improve libvirt error reporting for failed migrations (rhbz#528793)
- qemu driver support CPU hotplug (rhbz#533138)
- wrong (octal) device number for attaching USB devices (rhbz#549840)
- cannot save domain into root_squashing nfs export (rhbz#558763)
- assorted bug fixes and lots of cleanups

* Wed Mar  3 2010 Daniel P. Berrange <berrange@redhat.com> - 0.7.6-4
- Fix balloon parameter name handling in JSON mode (rhbz #566261)

* Fri Feb 26 2010 Daniel P. Berrange <berrange@redhat.com> - 0.7.6-3
- Fix balloon units handling in JSON mode (rhbz #566261)
- Invoke qmp_capabilities at monitor startup (rhbz #563189)

* Wed Feb 10 2010 Daniel Veillard <veillard@redhat.com> - 0.7.6-2
- enable JSON interface, desactivated by default in 0.7.6
- Resolves: rhbz#563189
- make sure cgroups are installed and that cgconfig service is on
- Resolves: rhbz#531263

* Wed Feb  3 2010 Daniel Veillard <veillard@redhat.com> - 0.7.6-1
- upstream release of 0.7.6
- Use QEmu new device adressing when possible
- Implement CPU topology support for QEMU driver
- Implement SCSI controller hotplug/unplug for QEMU
- Implement support for multi IQN
- a lot of fixes and improvements
- Resolves: rhbz#558761

* Fri Jan 22 2010 Daniel Veillard <veillard@redhat.com> - 0.7.6-0.pre20100121
- push updated prerelease version of 0.7.6 for testing in Beta1
- Resolves: rhbz#515213

* Thu Jan 21 2010 Daniel Veillard <veillard@redhat.com> - 0.7.6-0.pre20100121
- Push a prerelease version of 0.7.6 for testing in Beta1
- Allow specifying -cpu model/flags for qemu
- Resolves: rhbz#515213
- Add async qemu machine protocol to libvirt based on JSON QEmu API
- Resolves: rhbz#518701
- Allow for static PCI address assignment to all devices
- Resolves: rhbz#481924
- expose qemu's -fda fat:floppy feature (525074)
- configuration of virtual CPU topology (sockets, threads, cores) (538015)
- rewrite file chown'ing code to use security driver framework (547545 )
- cannot create a headless KVM virtual machine (548127)
- Improve virsh schedular parameters documentation (548485)
- Fail to delete a inactive pool using command "virsh pool-delete" (530985)
- virsh man page updation for using container (lxc:///) (528709)
- Command 'virsh vcpuinfo' returns libvirt error in RHEL6 with KVM (522829)
- Expose information about host CPU flags in capabilities (518062)

* Fri Jan 15 2010 Daniel P. Berrange <berrange@redhat.com> - 0.7.5-2
- Rebuild for libparted soname change (rhbz #555741)

* Wed Dec 23 2009 Daniel Veillard <veillard@redhat.com> - 0.7.5-1
- Add new API virDomainMemoryStats
- Public API and domain extension for CPU flags
- vbox: Add support for version 3.1
- Support QEMU's virtual FAT block device driver
- a lot of fixes

* Fri Nov 20 2009 Daniel Veillard <veillard@redhat.com> - 0.7.4-1
- upstream release of 0.7.4
- udev node device backend
- API to check object properties
- better QEmu monitor processing
- MAC address based port filtering for qemu
- support IPv6 and multiple addresses per interfaces
- a lot of fixes

* Thu Nov 19 2009 Daniel P. Berrange <berrange@redhat.com> - 0.7.2-6
- Really fix restore file labelling this time

* Wed Nov 11 2009 Daniel P. Berrange <berrange@redhat.com> - 0.7.2-5
- Disable numactl on s390[x]. Again.

* Wed Nov 11 2009 Daniel P. Berrange <berrange@redhat.com> - 0.7.2-4
- Fix QEMU save/restore permissions / labelling

* Thu Oct 29 2009 Mark McLoughlin <markmc@redhat.com> - 0.7.2-3
- Avoid compressing small log files (#531030)

* Thu Oct 29 2009 Mark McLoughlin <markmc@redhat.com> - 0.7.2-2
- Make libvirt-devel require libvirt-client, not libvirt
- Fix qemu machine types handling

* Wed Oct 14 2009 Daniel Veillard <veillard@redhat.com> - 0.7.2-1
- Upstream release of 0.7.2
- Allow to define ESX domains
- Allows suspend and resulme of LXC domains
- API for data streams
- many bug fixes

* Tue Oct 13 2009 Mark McLoughlin <markmc@redhat.com> - 0.7.1-12
- Fix restore of qemu guest using raw save format (#523158)

* Fri Oct  9 2009 Mark McLoughlin <markmc@redhat.com> - 0.7.1-11
- Fix libvirtd memory leak during error reply sending (#528162)
- Add several PCI hot-unplug typo fixes from upstream

* Tue Oct  6 2009 Mark McLoughlin <markmc@redhat.com> - 0.7.1-10
- Create /var/log/libvirt/{lxc,uml} dirs for logrotate
- Make libvirt-python dependon on libvirt-client
- Sync misc minor changes from upstream spec

* Tue Oct  6 2009 Mark McLoughlin <markmc@redhat.com> - 0.7.1-9
- Change logrotate config to weekly (#526769)

* Thu Oct  1 2009 Mark McLoughlin <markmc@redhat.com> - 0.7.1-8
- Disable sound backend, even when selinux is disabled (#524499)
- Re-label qcow2 backing files (#497131)

* Wed Sep 30 2009 Mark McLoughlin <markmc@redhat.com> - 0.7.1-7
- Fix USB device passthrough (#522683)

* Mon Sep 21 2009 Chris Weyl <cweyl@alumni.drew.edu> - 0.7.1-6
- rebuild for libssh2 1.2

* Mon Sep 21 2009 Mark McLoughlin <markmc@redhat.com> - 0.7.1-5
- Don't set a bogus error in virDrvSupportsFeature()
- Fix raw save format

* Thu Sep 17 2009 Mark McLoughlin <markmc@redhat.com> - 0.7.1-4
- A couple of hot-unplug memory handling fixes (#523953)

* Thu Sep 17 2009 Daniel Veillard <veillard@redhat.com> - 0.7.1-3
- disable numactl on s390[x]

* Thu Sep 17 2009 Daniel Veillard <veillard@redhat.com> - 0.7.1-2
- revamp of spec file for modularity and RHELs

* Tue Sep 15 2009 Daniel Veillard <veillard@redhat.com> - 0.7.1-1
- Upstream release of 0.7.1
- ESX, VBox driver updates
- mutipath support
- support for encrypted (qcow) volume
- compressed save image format for Qemu/KVM
- QEmu host PCI device hotplug support
- configuration of huge pages in guests
- a lot of fixes

* Mon Sep 14 2009 Mark McLoughlin <markmc@redhat.com> - 0.7.1-0.2.gitfac3f4c
- Update to newer snapshot of 0.7.1
- Stop libvirt using untrusted 'info vcpus' PID data (#520864)
- Support relabelling of USB and PCI devices
- Enable multipath storage support
- Restart libvirtd upon RPM upgrade

* Sun Sep  6 2009 Mark McLoughlin <markmc@redhat.com> - 0.7.1-0.1.gitg3ef2e05
- Update to pre-release git snapshot of 0.7.1
- Drop upstreamed patches

* Wed Aug 19 2009 Mark McLoughlin <markmc@redhat.com> - 0.7.0-6
- Fix migration completion with newer versions of qemu (#516187)

* Wed Aug 19 2009 Mark McLoughlin <markmc@redhat.com> - 0.7.0-5
- Add PCI host device hotplug support
- Allow PCI bus reset to reset other devices (#499678)
- Fix stupid PCI reset error message (bug #499678)
- Allow PM reset on multi-function PCI devices (bug #515689)
- Re-attach PCI host devices after guest shuts down (bug #499561)
- Fix list corruption after disk hot-unplug
- Fix minor 'virsh nodedev-list --tree' annoyance

* Thu Aug 13 2009 Daniel P. Berrange <berrange@redhat.com> - 0.7.0-4
- Rewrite policykit support (rhbz #499970)
- Log and ignore NUMA topology problems (rhbz #506590)

* Mon Aug 10 2009 Mark McLoughlin <markmc@redhat.com> - 0.7.0-3
- Don't fail to start network if ipv6 modules is not loaded (#516497)

* Thu Aug  6 2009 Mark McLoughlin <markmc@redhat.com> - 0.7.0-2
- Make sure qemu can access kernel/initrd (bug #516034)
- Set perms on /var/lib/libvirt/boot to 0711 (bug #516034)

* Wed Aug  5 2009 Daniel Veillard <veillard@redhat.com> - 0.7.0-1
- ESX, VBox3, Power Hypervisor drivers
- new net filesystem glusterfs
- Storage cloning for LVM and Disk backends
- interface implementation based on netcf
- Support cgroups in QEMU driver
- QEmu hotplug NIC support
- a lot of fixes

* Fri Jul  3 2009 Daniel Veillard <veillard@redhat.com> - 0.6.5-1
- release of 0.6.5

* Fri May 29 2009 Daniel Veillard <veillard@redhat.com> - 0.6.4-1
- release of 0.6.4
- various new APIs

* Fri Apr 24 2009 Daniel Veillard <veillard@redhat.com> - 0.6.3-1
- release of 0.6.3
- VirtualBox driver

* Fri Apr  3 2009 Daniel Veillard <veillard@redhat.com> - 0.6.2-1
- release of 0.6.2

* Fri Mar  4 2009 Daniel Veillard <veillard@redhat.com> - 0.6.1-1
- release of 0.6.1

* Sat Jan 31 2009 Daniel Veillard <veillard@redhat.com> - 0.6.0-1
- release of 0.6.0

* Tue Nov 25 2008 Daniel Veillard <veillard@redhat.com> - 0.5.0-1
- release of 0.5.0

* Tue Sep 23 2008 Daniel Veillard <veillard@redhat.com> - 0.4.6-1
- release of 0.4.6

* Mon Sep  8 2008 Daniel Veillard <veillard@redhat.com> - 0.4.5-1
- release of 0.4.5

* Wed Jun 25 2008 Daniel Veillard <veillard@redhat.com> - 0.4.4-1
- release of 0.4.4
- mostly a few bug fixes from 0.4.3

* Thu Jun 12 2008 Daniel Veillard <veillard@redhat.com> - 0.4.3-1
- release of 0.4.3
- lots of bug fixes and small improvements

* Tue Apr  8 2008 Daniel Veillard <veillard@redhat.com> - 0.4.2-1
- release of 0.4.2
- lots of bug fixes and small improvements

* Mon Mar  3 2008 Daniel Veillard <veillard@redhat.com> - 0.4.1-1
- Release of 0.4.1
- Storage APIs
- xenner support
- lots of assorted improvements, bugfixes and cleanups
- documentation and localization improvements

* Tue Dec 18 2007 Daniel Veillard <veillard@redhat.com> - 0.4.0-1
- Release of 0.4.0
- SASL based authentication
- PolicyKit authentication
- improved NUMA and statistics support
- lots of assorted improvements, bugfixes and cleanups
- documentation and localization improvements

* Sun Sep 30 2007 Daniel Veillard <veillard@redhat.com> - 0.3.3-1
- Release of 0.3.3
- Avahi support
- NUMA support
- lots of assorted improvements, bugfixes and cleanups
- documentation and localization improvements

* Tue Aug 21 2007 Daniel Veillard <veillard@redhat.com> - 0.3.2-1
- Release of 0.3.2
- API for domains migration
- APIs for collecting statistics on disks and interfaces
- lots of assorted bugfixes and cleanups
- documentation and localization improvements

* Tue Jul 24 2007 Daniel Veillard <veillard@redhat.com> - 0.3.1-1
- Release of 0.3.1
- localtime clock support
- PS/2 and USB input devices
- lots of assorted bugfixes and cleanups
- documentation and localization improvements

* Mon Jul  9 2007 Daniel Veillard <veillard@redhat.com> - 0.3.0-1
- Release of 0.3.0
- Secure remote access support
- unification of daemons
- lots of assorted bugfixes and cleanups
- documentation and localization improvements

* Fri Jun  8 2007 Daniel Veillard <veillard@redhat.com> - 0.2.3-1
- Release of 0.2.3
- lot of assorted bugfixes and cleanups
- support for Xen-3.1
- new scheduler API

* Tue Apr 17 2007 Daniel Veillard <veillard@redhat.com> - 0.2.2-1
- Release of 0.2.2
- lot of assorted bugfixes and cleanups
- preparing for Xen-3.0.5

* Thu Mar 22 2007 Jeremy Katz <katzj@redhat.com> - 0.2.1-2.fc7
- don't require xen; we don't need the daemon and can control non-xen now
- fix scriptlet error (need to own more directories)
- update description text

* Fri Mar 16 2007 Daniel Veillard <veillard@redhat.com> - 0.2.1-1
- Release of 0.2.1
- lot of bug and portability fixes
- Add support for network autostart and init scripts
- New API to detect the virtualization capabilities of a host
- Documentation updates

* Fri Feb 23 2007 Daniel P. Berrange <berrange@redhat.com> - 0.2.0-4.fc7
- Fix loading of guest & network configs

* Fri Feb 16 2007 Daniel P. Berrange <berrange@redhat.com> - 0.2.0-3.fc7
- Disable kqemu support since its not in Fedora qemu binary
- Fix for -vnc arg syntax change in 0.9.0  QEMU

* Thu Feb 15 2007 Daniel P. Berrange <berrange@redhat.com> - 0.2.0-2.fc7
- Fixed path to qemu daemon for autostart
- Fixed generation of <features> block in XML
- Pre-create config directory at startup

* Wed Feb 14 2007 Daniel Veillard <veillard@redhat.com> 0.2.0-1.fc7
- support for KVM and QEmu
- support for network configuration
- assorted fixes

* Mon Jan 22 2007 Daniel Veillard <veillard@redhat.com> 0.1.11-1.fc7
- finish inactive Xen domains support
- memory leak fix
- RelaxNG schemas for XML configs

* Wed Dec 20 2006 Daniel Veillard <veillard@redhat.com> 0.1.10-1.fc7
- support for inactive Xen domains
- improved support for Xen display and vnc
- a few bug fixes
- localization updates

* Thu Dec  7 2006 Jeremy Katz <katzj@redhat.com> - 0.1.9-2
- rebuild against python 2.5

* Wed Nov 29 2006 Daniel Veillard <veillard@redhat.com> 0.1.9-1
- better error reporting
- python bindings fixes and extensions
- add support for shareable drives
- add support for non-bridge style networking
- hot plug device support
- added support for inactive domains
- API to dump core of domains
- various bug fixes, cleanups and improvements
- updated the localization

* Tue Nov  7 2006 Daniel Veillard <veillard@redhat.com> 0.1.8-3
- it's pkgconfig not pgkconfig !

* Mon Nov  6 2006 Daniel Veillard <veillard@redhat.com> 0.1.8-2
- fixing spec file, added %dist, -devel requires pkgconfig and xen-devel
- Resolves: rhbz#202320

* Mon Oct 16 2006 Daniel Veillard <veillard@redhat.com> 0.1.8-1
- fix missing page size detection code for ia64
- fix mlock size when getting domain info list from hypervisor
- vcpu number initialization
- don't label crashed domains as shut off
- fix virsh man page
- blktapdd support for alternate drivers like blktap
- memory leak fixes (xend interface and XML parsing)
- compile fix
- mlock/munlock size fixes

* Fri Sep 22 2006 Daniel Veillard <veillard@redhat.com> 0.1.7-1
- Fix bug when running against xen-3.0.3 hypercalls
- Fix memory bug when getting vcpus info from xend

* Fri Sep 22 2006 Daniel Veillard <veillard@redhat.com> 0.1.6-1
- Support for localization
- Support for new Xen-3.0.3 cdrom and disk configuration
- Support for setting VNC port
- Fix bug when running against xen-3.0.2 hypercalls
- Fix reconnection problem when talking directly to http xend

* Tue Sep  5 2006 Jeremy Katz <katzj@redhat.com> - 0.1.5-3
- patch from danpb to support new-format cd devices for HVM guests

* Tue Sep  5 2006 Daniel Veillard <veillard@redhat.com> 0.1.5-2
- reactivating ia64 support

* Tue Sep  5 2006 Daniel Veillard <veillard@redhat.com> 0.1.5-1
- new release
- bug fixes
- support for new hypervisor calls
- early code for config files and defined domains

* Mon Sep  4 2006 Daniel Berrange <berrange@redhat.com> - 0.1.4-5
- add patch to address dom0_ops API breakage in Xen 3.0.3 tree

* Mon Aug 28 2006 Jeremy Katz <katzj@redhat.com> - 0.1.4-4
- add patch to support paravirt framebuffer in Xen

* Mon Aug 21 2006 Daniel Veillard <veillard@redhat.com> 0.1.4-3
- another patch to fix network handling in non-HVM guests

* Thu Aug 17 2006 Daniel Veillard <veillard@redhat.com> 0.1.4-2
- patch to fix virParseUUID()

* Wed Aug 16 2006 Daniel Veillard <veillard@redhat.com> 0.1.4-1
- vCPUs and affinity support
- more complete XML, console and boot options
- specific features support
- enforced read-only connections
- various improvements, bug fixes

* Wed Aug  2 2006 Jeremy Katz <katzj@redhat.com> - 0.1.3-6
- add patch from pvetere to allow getting uuid from libvirt

* Wed Aug  2 2006 Jeremy Katz <katzj@redhat.com> - 0.1.3-5
- build on ia64 now

* Thu Jul 27 2006 Jeremy Katz <katzj@redhat.com> - 0.1.3-4
- don't BR xen, we just need xen-devel

* Thu Jul 27 2006 Daniel Veillard <veillard@redhat.com> 0.1.3-3
- need rebuild since libxenstore is now versionned

* Mon Jul 24 2006 Mark McLoughlin <markmc@redhat.com> - 0.1.3-2
- Add BuildRequires: xen-devel

* Wed Jul 12 2006 Jesse Keating <jkeating@redhat.com> - 0.1.3-1.1
- rebuild

* Tue Jul 11 2006 Daniel Veillard <veillard@redhat.com> 0.1.3-1
- support for HVM Xen guests
- various bugfixes

* Mon Jul  3 2006 Daniel Veillard <veillard@redhat.com> 0.1.2-1
- added a proxy mechanism for read only access using httpu
- fixed header includes paths

* Wed Jun 21 2006 Daniel Veillard <veillard@redhat.com> 0.1.1-1
- extend and cleanup the driver infrastructure and code
- python examples
- extend uuid support
- bug fixes, buffer handling cleanups
- support for new Xen hypervisor API
- test driver for unit testing
- virsh --conect argument

* Mon Apr 10 2006 Daniel Veillard <veillard@redhat.com> 0.1.0-1
- various fixes
- new APIs: for Node information and Reboot
- virsh improvements and extensions
- documentation updates and man page
- enhancement and fixes of the XML description format

* Tue Feb 28 2006 Daniel Veillard <veillard@redhat.com> 0.0.6-1
- added error handling APIs
- small bug fixes
- improve python bindings
- augment documentation and regression tests

* Thu Feb 23 2006 Daniel Veillard <veillard@redhat.com> 0.0.5-1
- new domain creation API
- new UUID based APIs
- more tests, documentation, devhelp
- bug fixes

* Fri Feb 10 2006 Daniel Veillard <veillard@redhat.com> 0.0.4-1
- fixes some problems in 0.0.3 due to the change of names

* Wed Feb  8 2006 Daniel Veillard <veillard@redhat.com> 0.0.3-1
- changed library name to libvirt from libvir, complete and test the python
  bindings

* Sun Jan 29 2006 Daniel Veillard <veillard@redhat.com> 0.0.2-1
- upstream release of 0.0.2, use xend, save and restore added, python bindings
  fixed

* Wed Nov  2 2005 Daniel Veillard <veillard@redhat.com> 0.0.1-1
- created
