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
%define with_xen_proxy     0%{!?_without_xen_proxy:%{server_drivers}}
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
# or libxenserver (xenapi)
%if 0%{?rhel}
%define with_openvz 0
%define with_vbox 0
%define with_uml 0
%define with_one 0
%define with_phyp 0
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

# If Xen isn't turned on, we shouldn't build the xen proxy either
%if ! %{with_xen}
%define with_xen_proxy 0
%endif

# Fedora doesn't have any QEMU on ppc64 - only ppc
%if 0%{?fedora}
%ifarch ppc64
%define with_qemu 0
%endif
%endif

# PolicyKit was introduced in Fedora 8 / RHEL-6 or newer, allowing
# the setuid Xen proxy to be killed off
%if 0%{?fedora} >= 8 || 0%{?rhel} >= 6
%define with_polkit    0%{!?_without_polkit:1}
%define with_xen_proxy 0
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


Summary: Library providing a simple API virtualization
Name: libvirt
Version: 0.8.1
Release: 27%{?dist}.5%{?extra_release}
License: LGPLv2+
Group: Development/Libraries
Source: http://libvirt.org/sources/libvirt-%{version}.tar.gz


# 563189: Turn on JSON mode and -netdev usage for RHEL6 binary
Patch0: libvirt-0.8.0-json-netdev.patch
# Fix comment for <video> tag in domain RNG schema
# upstreamed
Patch1: libvirt-0.8.0-rng-video-comment.patch
# Add a QXL graphics card type to domain XML schema
Patch2: libvirt-0.8.0-xql-video-xml.patch
# Add a <graphics> type for SPICE protocol
Patch3: libvirt-0.8.0-spice-graphic-xml.patch
# Fix QEMU command building errors to reflect unsupported config
# upstreamed
#Patch4: libvirt-0.8.0-qemu-cmdline-error.patch
# Implement RHEL-6.0 KVM QXL support in QEMU driver
Patch5: libvirt-0.8.0-xql-qemu-driver.patch
# Implement RHEL-6 KVM support for SPICE graphics
Patch6: libvirt-0.8.0-spice-qemu-driver.patch
# Support automatic port number allocation for SPICE
Patch7: libvirt-0.8.0-spice-port-allocation.patch
# Add SPICE support for QEMU driver configuration file
Patch8: libvirt-0.8.0-spice-qemu-config.patch
# Define XML syntax for password expiry
Patch9: libvirt-0.8.0-xml-passwd-expiry.patch
# Support password expiry in the QEMU driver
Patch10: libvirt-0.8.0-passwd-expiry-qemu.patch
# Support multiple QXL video cards
Patch11: libvirt-0.8.0-multiple-xql-video.patch
# Support SPICE channel security options
Patch12: libvirt-0.8.0-spice-security-options.patch
# Emit graphics events when a SPICE client (dis)connects
Patch13: libvirt-0.8.0-spice-connection-events.patch

# Don't wipe generated iface target in active domains
# https://bugzilla.redhat.com/show_bug.cgi?id=588046
Patch14: libvirt-0.8.1-keep-active-iface.patch

# lxc: Fix domain lookup and error handling
# https://bugzilla.redhat.com/show_bug.cgi?id=586361
Patch15: libvirt-0.8.1-lxc-domain-inactive-error.patch
Patch16: libvirt-0.8.1-lxc-lookup-uuid.patch
Patch17: libvirt-0.8.1-lxc-set-mem-active.patch

# Fix protocol breakage introduced in libvirt-0.8.0
Patch18: libvirt-0.8.1-nwfilter-remote-error.patch

# Add support for NIC hotplug using netdev_add in QEMU
# https://bugzilla.redhat.com/show_bug.cgi?id=589978
Patch19: libvirt-0.8.1-qemu-nic-hotplug.patch

# Support seamless migration of SPICE graphics clients
# https://bugzilla.redhat.com/show_bug.cgi?id=589989
# https://bugzilla.redhat.com/show_bug.cgi?id=591551
Patch20: libvirt-0.8.1-seamless-spice-migration.patch

# the libvirt API XML didn't got rebuilt at release time
# results in missing entry points for python bindings
# https://bugzilla.redhat.com/show_bug.cgi?id=589453
Patch21: libvirt-0.8.1-api-rebuild.patch

# fix 2 possible crashes in JSON events raised by DanK
# https://bugzilla.redhat.com/show_bug.cgi?id=586353 comment 5
Patch22: libvirt-0.8.1-json-graphics-typo.patch
Patch23: libvirt-0.8.1-ioerror-reason-crash.patch

# Fix handling of disk backing stores with cgroups
# https://bugzilla.redhat.com/show_bug.cgi?id=581476
Patch24: libvirt-0.8.1-cgroups-backing-store.patch

# virsh schedinfo --set does not report an error for unknown parameters
# https://bugzilla.redhat.com/show_bug.cgi?id=586632
Patch25: libvirt-0.8.1-virsh-schedinfo-param.patch

# Apply fixes for nwfilter
# https://bugzilla.redhat.com/show_bug.cgi?id=588554
Patch26: libvirt-0.8.1-nwfilter-fix-rules-appl.patch
Patch27: libvirt-0.8.1-nwfilter-update-skip.patch

# Fix hang during concurrent guest migrations
# https://bugzilla.redhat.com/show_bug.cgi?id=582278
Patch28: libvirt-0.8.1-remote-close-watch.patch
Patch29: libvirt-0.8.1-monitor-refcount-event.patch

# Query qemu for allocated size of qcow image
# https://bugzilla.redhat.com/show_bug.cgi?id=526289
Patch30: libvirt-0.8.1-qemu-block-allocation.patch

# Skip the reset of user/group/security label on shared fs
# https://bugzilla.redhat.com/show_bug.cgi?id=578889
Patch31: libvirt-0.8.1-security-label-shared-filesystem.patch

# Make saved state labelling ignore the dynamic_ownership parameter
# https://bugzilla.redhat.com/show_bug.cgi?id=588562
Patch32: libvirt-0.8.1-dynamic-ownership.patch

# Fix & protect against NULL pointer dereference in monitor code
# https://bugzilla.redhat.com/show_bug.cgi?id=591076
Patch33: libvirt-0.8.1-fix-null-pointer-in-monitor.patch
Patch34: libvirt-0.8.1-protect-null-pointer-in-monitor.patch

# Fix virFileResolveLink return value
# https://bugzilla.redhat.com/show_bug.cgi?id=591363
Patch35: libvirt-0.8.1-fix-resolve-link-return-value.patch

# Add support for SSE4.1 and SSE4.2 CPU features
# https://bugzilla.redhat.com/show_bug.cgi?id=592977
Patch36: libvirt-0.8.1-support-SSE4.patch

# Fix swapping of PCI vendor & product names in udev backend
# https://bugzilla.redhat.com/show_bug.cgi?id=578419
Patch37: libvirt-0.8.1-fix-vendor-product-swap.patch

# Fix cgroup setup code to cope with root squashing NFS
# https://bugzilla.redhat.com/show_bug.cgi?id=593193
Patch38: libvirt-0.8.1-fix-cgroup-root-squash-nfs.patch

# Fix startup error reporting race
# https://bugzilla.redhat.com/show_bug.cgi?id=591272
Patch39: libvirt-0.8.1-fix-startup-error-reporting.patch

# Fix sign extension error in libvirt's parsing of qemu options
# https://bugzilla.redhat.com/show_bug.cgi?id=592070
Patch40: libvirt-0.8.1-qemu_conf-fix-flag-value.patch

# Graceful shutdown/suspend of libvirt guests on host shutdown
# https://bugzilla.redhat.com/show_bug.cgi?id=566647
Patch41: libvirt-0.8.1-refactor-qemudDomainRestore.patch
Patch42: libvirt-0.8.1-refactor-virDomainAssignDef.patch
Patch43: libvirt-0.8.1-refactor-qemudDomainStart.patch
Patch44: libvirt-0.8.1-autostart-domains.patch
Patch45: libvirt-0.8.1-init-script-for-handling-guests.patch

# Fix pci device hotplug
# https://bugzilla.redhat.com/show_bug.cgi?id=572867
Patch46: libvirt-0.8.1-fix-guestAddr-corruption.patch
Patch47: libvirt-0.8.1-release-PCI-address.patch
Patch48: libvirt-0.8.1-rename-tap-devs-fd-array.patch
Patch49: libvirt-0.8.1-open-PCI-dev-sysfs.patch
Patch50: libvirt-0.8.1-fix-hotplug-methods-flags.patch

# Support 802.1Qbg and bh
# https://bugzilla.redhat.com/show_bug.cgi?id=532760
# https://bugzilla.redhat.com/show_bug.cgi?id=570949
# https://bugzilla.redhat.com/show_bug.cgi?id=590110
# https://bugzilla.redhat.com/show_bug.cgi?id=570923
Patch51: libvirt-0.8.1-introduce-libnl-dependency.patch
Patch52: libvirt-0.8.1-expose-host-uuid.patch
Patch53: libvirt-0.8.1-parse-802.1Qbg_bh-xml.patch
Patch54: libvirt-0.8.1-build-fix-compilation-without-macvtap.patch
Patch55: libvirt-0.8.1-macvtap-cannot-support-target-device-name.patch
Patch56: libvirt-0.8.1-add-802.1Qbh-and-802.1Qbg-handling.patch

# Ensure virtio serial has stable addressing
Patch57: libvirt-0.8.1-virtio-serial-port-number.patch
Patch58: libvirt-0.8.1-fix-auto-add-virtio-serial.patch
Patch59: libvirt-0.8.1-fix-broken-virtio-serial-test.patch

# SELinux socket labelling on QEMU monitor socket for MLS
Patch60: libvirt-0.8.1-MLS-mode-socket-labelling.patch

# Fix enumeration of partitions in disks with a trailing digit in path
Patch61: libvirt-0.8.1-fix-partitions-trailing-digit.patch

# Enable probing of VPC disk format type
Patch62: libvirt-0.8.1-enable-VPC-disk-format-probing.patch

# Delete UNIX domain sockets upon daemon shutdown
Patch63: libvirt-0.8.1-remove-domain-sockets-on-shutdown.patch

# Fix Migration failure 'canonical hostname pointed to localhost'
Patch64: libvirt-0.8.1-fix-virGetHostname.patch

# Fix up the python bindings for snapshotting
Patch65: libvirt-0.8.1-snapshot-python.patch

# Sanitize pool target paths
Patch66: libvirt-0.8.1-sanitize-pool-paths.patch

# Prevent host network conflicts
Patch67: libvirt-0.8.1-prevent-host-network-conflicts.patch

# Touch libvirt-guests lockfile
Patch68: libvirt-0.8.1-touch-libvirt-guests-lockfile.patch

# Add qemu.conf option for clearing capabilities
Patch69: libvirt-0.8.1-qemu-clearing-capabilities-option.patch

# Add support for launching guest in paused state
Patch70: libvirt-0.8.1-add-start-paused-flag.patch
Patch71: libvirt-0.8.1-allow-start-guest-paused.patch
Patch72: libvirt-0.8.1-add-virsh-start-paused.patch

# Add virsh vol-pool command
Patch73: libvirt-0.8.1-add-virsh-vol-pool.patch

# Add vol commands to virsh man page
Patch74: libvirt-0.8.1-add-vol-man-page.patch

# Remove bogus migrate error messages
Patch75: libvirt-0.8.1-remove-bogus-migrate-errors.patch

# Add multiIQN XML output
Patch76: libvirt-0.8.1-add-multiIQN-XML-dump.patch
Patch77: libvirt-0.8.1-add-multiIQN-tests.patch

# Fix udev node device parent-child device relationships
Patch78: libvirt-0.8.1-fix-udev-relationships.patch

# Fix leaks in udev device add/remove
Patch79: libvirt-0.8.1-fix-udev-add-remove-leak.patch

# Fix device destroy return value
Patch80: libvirt-0.8.1-fix-dev-destroy-retval.patch

# Update nodedev scsi_host data before use
Patch81: libvirt-0.8.1-update-scsi_host-data.patch

# Display wireless devices in nodedev list
Patch82: libvirt-0.8.1-display-wlan-devs.patch

# Show pool and domain persistence
Patch83: libvirt-0.8.1-show-persistence-autostart.patch

# Fix cleanup after failing to hotplug a PCI device
Patch84: libvirt-0.8.1-dont-raise-selinux-errors.patch
Patch85: libvirt-0.8.1-reattach-pci-dev-on-fail.patch

# Add '-nodefconfig' command line arg to QEMU
Patch86: libvirt-0.8.1-add-nodefconfig-arg.patch

# Switch to private redhat namespace for QMP I/O error reason
Patch87: libvirt-0.8.1-use-QMP-RH-namespace-ioerror-reason.patch

# Improve error messages for missing drivers & unsupported functions
Patch88: libvirt-0.8.1-improve-err-msg.patch

# macvtap: get interface index if not provided
Patch89: libvirt-0.8.1-macvtap-get-interface-index.patch

# Fix leaks in remote code
Patch90: libvirt-0.8.1-fix-leaks-in-remote-code.patch

# Add an optional switch --uuid to the virsh vol-pool command
Patch91: libvirt-0.8.1-add-vol-pool-uuid-switch.patch

# Change per-connection hashes to be indexed by UUIDs
Patch92: libvirt-0.8.1-index-hashes-by-uuid.patch
Patch93: libvirt-0.8.1-remove-non-null-uuid-check.patch
Patch94: libvirt-0.8.1-do-not-free-static-buffer-with-uuid.patch
Patch95: libvirt-0.8.1-uuid-hash-misc-cleanups.patch

# Run virsh from libvirt-guests script with /dev/null on stdin
Patch96: libvirt-0.8.1-run-virsh-null-stdin.patch

# Speed up domain save
Patch97: libvirt-0.8.1-fix-possible-free-ptr-deref.patch
Patch98: libvirt-0.8.1-increase-dd-block-size.patch
Patch99: libvirt-0.8.1-reduce-wasted-padding.patch

# Fix reference counting bugs on qemu monitor
Patch100: libvirt-0.8.1-use-virDomainIsActive.patch
Patch101: libvirt-0.8.1-fix-qemuMonitor-reference-leak.patch

# Add missing action parameter in IO error callback
Patch102: libvirt-0.8.1-add-io-err-action-parameter.patch

# Do not block during incoming migration
Patch103: libvirt-0.8.1-do-not-block-during-incoming-migration.patch

# Label serial devices
Patch104: libvirt-0.8.1-add-virDomainChrDefForeach.patch
Patch105: libvirt-0.8.1-label-serial-devs.patch

# parthelper: fix compilation without optimization
Patch106: libvirt-0.8.1-fix-compile-without-optimization.patch

# Fix name/UUID uniqueness checking in storage/network
Patch107: libvirt-0.8.1-add-virStoragePoolObjIsDuplicate.patch
Patch108: libvirt-0.8.1-add-virNetworkObjIsDuplicate.patch
Patch109: libvirt-0.8.1-fix-missing-pool-err-code.patch

# Don't squash file permissions when migration fails
Patch110: libvirt-0.8.1-do-not-squash-perms-on-migration-fail.patch

# Properly handle 'usbX' sysfs files
Patch111: libvirt-0.8.1-handle-usbX-devices.patch

# add pool support to vol-key command & improve vol commands help
Patch112: libvirt-0.8.1-add-pool-arg-to-vol-key.patch
Patch113: libvirt-0.8.1-improve-vol-help.patch

# document attach-disk better
Patch114: libvirt-0.8.1-improve-attach-disk-doc.patch

# Config iptables to allow tftp port if network <tftp> element exists
Patch115: libvirt-0.8.1-iptables-allow-tftp.patch

# Fix failure to generate python bindings when libvirt.h.in is updated
Patch116: libvirt-0.8.1-fix-binding-generation.patch

# Allow all interface names
Patch117: libvirt-0.8.1-remove-isValidIfname.patch

# Fix nodedevice refcounting
Patch118: libvirt-0.8.1-fix-nodedevice-refcount.patch

# Move nwfilter functions inside extern C and fix a locking bug
Patch119: libvirt-0.8.1-nwfilter-fixes.patch

# Fix failure to restore qemu domains with selinux enforcing
Patch120: libvirt-0.8.1-add-stdin_path-to-qemudStartVMDaemon-args.patch
Patch121: libvirt-0.8.1-set-proper-selinux-label-on-image-file.patch
Patch122: libvirt-0.8.1-enhance-virStorageFileIsSharedFS.patch
Patch123: libvirt-0.8.1-use-virStorageFileIsSharedFS-in-qemudDomainSaveFlag.patch
Patch124: libvirt-0.8.1-ignore-domainSetSecurityAllLabel-failure-in-restore.patch
Patch125: libvirt-0.8.1-check-stdin_path-for-NULL.patch

# Check for presence of qemu -nodefconfig option before using it
Patch126: libvirt-0.8.1-check-for-nodefconfig.patch
Patch127: libvirt-0.8.1-fix-nodefconfig-test-failure.patch

# Don't invoke destroy callback from qemuMonitorOpen() failure paths
Patch128: libvirt-0.8.1-remove-callback-if-construction-fails.patch

# virFileResolveLink: guarantee an absolute path
Patch129: libvirt-0.8.1-guarantee-absolute-path.patch

# SPICE patches have translatable strings without format args
Patch130: libvirt-0.8.1-fix-translatable-strings.patch

# No way to pass disk format type to pool-define-as nor pool-create-as
Patch131: libvirt-0.8.1-add-src-format-arg-to-pool-cmds.patch
Patch132: libvirt-0.8.1-src-format-arg-manpage.patch

# Fix enforcement of direction of traffic for rules describing incoming traffic
Patch133: libvirt-0.8.1-nwfilter-match-target-incoming-traffic.patch
Patch134: libvirt-0.8.1-add-iptables-state-XML-attribute.patch

# Clarify virsh help pool-create-as text
Patch135: libvirt-0.8.1-clarify-pool-create-as-help.patch

# Support virtio disk hotplug in JSON mode
Patch136: libvirt-0.8.1-JSON-mode-virtio-disk-hotplug.patch

# Fix QEMU monitor JSON crash
Patch137: libvirt-0.8.1-fix-QEMU-monitor-JSON-crash.patch

# CVE-2010-2237 CVE-2010-2238 CVE-2010-2239
Patch138: libvirt-0.8.1-extract-backing-store-format.patch
Patch139: libvirt-0.8.1-remove-type-field-from-FileTypeInfo-struct.patch
Patch140: libvirt-0.8.1-refactor-virStorageFileGetMetadataFromFD.patch
Patch141: libvirt-0.8.1-require-passing-format-to-virStorageFileGetMetadata.patch
Patch142: libvirt-0.8.1-add-API-for-iterating-over-disk-paths.patch
Patch143: libvirt-0.8.1-convert-disk-backing-store-loops-to-shared-helper-API.patch
Patch144: libvirt-0.8.1-pass-security-driver-object-to-callbacks.patch
Patch145: libvirt-0.8.1-disable-QEMU-driver-disk-probing.patch
Patch146: libvirt-0.8.1-allow-setting-disk-default-driver-name-type.patch
Patch147: libvirt-0.8.1-rewrite-qemu-img-backing-store-format-handling.patch
Patch148: libvirt-0.8.1-use-extract-backing-store-format-in-storage-volume-lookup.patch

# CVE-2010-2242 Apply a source port mapping to virtual network masquerading
Patch149: libvirt-0.8.1-apply-source-port-mapping-to-masq.patch

# Fix hang if QEMU exits (almost) immediately
Patch150: libvirt-0.8.1-fix-hang-if-QEMU-exits-almost-immediately.patch

# Support new CPU models provided by qemu-kvm
Patch151: libvirt-0.8.1-add-CPU-vendor-support.patch
Patch152: libvirt-0.8.1-add-new-models-from-qemu-target-x86_64.conf.patch

# Fix comparison of two host CPUs
Patch153: libvirt-0.8.1-fix-comparison-of-two-host-CPUs.patch

# Don't mess with the CPU returned by arch driver
Patch154: libvirt-0.8.1-dont-mess-with-the-CPU-returned-by-arch-driver.patch

# Fail when CPU type cannot be detected from XML
Patch155: libvirt-0.8.1-fail-when-CPU-type-cannot-be-detected-from-XML.patch

# Use -nodefconfig when probing for CPU models
Patch156: libvirt-0.8.1-use-nodefconfig-when-probing-for-CPU-models.patch

# cpuCompare: Fix crash on unexpected CPU XML
Patch157: libvirt-0.8.1-fix-crash-on-unexpected-CPU-XML.patch

# Properly report failure to create raw storage volume files
Patch158: libvirt-0.8.1-report-failure-to-create-raw-storage-volume-files.patch

# Fix IOErrorReasonCallback python bindings
Patch159: libvirt-0.8.1-fix-IOErrorReasonCallback-python-bindings.patch

# Parthelper: canonicalize block device paths
Patch160: libvirt-0.8.1-parthelper-canonicalize-blkdev-paths.patch

# Add iptables rule to fixup DHCP response checksum
Patch161: libvirt-0.8.1-fix-DHCP-checksum.patch

# Make PCI device ordering consistent with older releases
Patch162: libvirt-0.8.1-rearrange-VGA-IDE-controller-address-reservation.patch
Patch163: libvirt-0.8.1-represent-balloon-device-in-XML.patch
Patch164: libvirt-0.8.1-rearrange-PCI-device-address-assignment.patch
Patch165: libvirt-0.8.1-reserve-slot-1-for-PIIX3.patch

# Fix libvirtd hang during concurrent bi-directional migration
Patch166: libvirt-0.8.1-fix-concurrent-bidirectional.migration.patch

# Set a stable & high MAC addr for guest TAP devices
Patch167: libvirt-0.8.1-set-stable-MAC-for-guest-TAP-devs.patch

# Add character device backend activating QEMU internal spice agent
Patch168: libvirt-0.8.1-spice-agent-chardev.patch

# Make libvirt-guests initscript Fedora compliant
Patch169: libvirt-0.8.1-init-script-reject-extra-args.patch
Patch170: libvirt-0.8.1-init-script-set-useful-status.patch
Patch171: libvirt-0.8.1-init-script-add-required-cmds.patch

# Fix error message in guests init script when libvirtd isn't installed
Patch172: libvirt-0.8.1-init-script-fix-error-when-libvirtd-not-installed.patch

# Fix multiple PCI device assignment bugs
Patch173: libvirt-0.8.1-find-multiple-devs-on-bus.patch
Patch174: libvirt-0.8.1-refactor-qemuGetPciHostDeviceList.patch
Patch175: libvirt-0.8.1-add-helper-functions.patch
Patch176: libvirt-0.8.1-use-helper-functions.patch
Patch177: libvirt-0.8.1-fix-reset-logic.patch
Patch178: libvirt-0.8.1-force-FLR-on-for-buggy-SR-IOV-devs.patch
Patch179: libvirt-0.8.1-fix-race-in-pciInitDevice.patch

# Fix the ACS checking in the PCI code
Patch180: libvirt-0.8.1-pci-acs-checking-fix.patch

# Disable boot=on when not using KVM
Patch181: libvirt-0.8.1-no-kvm-no-boot-on.patch

# Don't leak delay string when freeing virInterfaceBridgeDefs
Patch182: libvirt-0.8.1-fix-host-bridge-interface-def-leak.patch

# Mitigate asynchronous device_del
Patch183: libvirt-0.8.1-mitigate-asynchronous-device_del.patch

# Fix PCI address allocation
Patch184: libvirt-0.8.1-fix-PCI-address-allocation.patch

# Make nodeinfo skip offline CPUs
Patch185: libvirt-0.8.1-nodeinfo-skip-offline-CPUs.patch

# Allow <memballoon type='none'/> to disable balloon support
Patch186: libvirt-0.8.1-balloon-none.patch

# A couple of patch to fix PXE boot on virtual network: 623951
Patch187: libvirt-0.8.1-pxe-boot.patch

# A couple of fix to restore tunneled migration
Patch188: libvirt-0.8.1-tunelled-migration.patch

# Fix problem with capabilities XML generation
Patch189: libvirt-0.8.1-log-XDR-serialization-failures.patch
Patch190: libvirt-0.8.1-improve-error-messages-when-RPC-reply-cannot-be-sent.patch
Patch191: libvirt-0.8.1-enable-debug-logging-of-capabilities-XML.patch
Patch192: libvirt-0.8.1-check-for-all-1s-CPU-mask.patch

# Correctly reserve and release PCI slots
Patch193: libvirt-0.8.1-fix-reserve-PCI-addrs-on-reconnect.patch
Patch194: libvirt-0.8.1-release-PCI-slot-on-detach.patch

### 6.0.z

Patch195: libvirt-qemu-Fix-JSON-migrate_set_downtime-command.patch
Patch196: libvirt-Make-SASL-work-over-UNIX-domain-sockets.patch
Patch197: libvirt-initgroups-in-qemudOpenAsUID.patch
Patch198: libvirt-root_squash-saga-virFileOperation-may-fail-with-EPERM.patch
Patch199: libvirt-qemu-check-for-vm-after-starting-a-job.patch
Patch209: libvirt-Change-return-value-of-VIR_DRV_SUPPORTS_FEATURE-to-bool.patch
Patch210: libvirt-qemu-Fix-a-possible-deadlock-in-p2p-migration.patch
Patch211: libvirt-Fix-funny-off-by-one-error-in-clock-variable.patch
Patch216: libvirt-qemu-call-drive_unplug-in-DetachPciDiskDevice.patch
Patch217: libvirt-qemu-call-drive_del-in-DetachPciDiskDevice.patch
Patch218: libvirt-qemu-Distinguish-between-domain-shutdown-and-crash.patch
Patch219: libvirt-qemu-plug-memory-leak.patch
Patch220: libvirt-security-storage-plug-memory-leaks-for-security_context_t.patch
Patch221: libvirt-libvirtd-avoid-memory-leak-on-shutdown.patch
Patch222: libvirt-qemu-plug-memory-leak_2.patch
Patch223: libvirt-Fix-memory-leak-in-logging-setup.patch
Patch224: libvirt-qemud-fix-memory-leak-in-io-error-events.patch
Patch225: libvirt-daemon-threads-plug-a-memory-leak.patch
Patch226: libvirt-selinux-avoid-memory-overhead-of-matchpathcon.patch
Patch227: libvirt-Add-missing-checks-for-read-only-connections.patch

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
URL: http://libvirt.org/
BuildRequires: python-devel
BuildRequires: libnl-devel >= 1.1
BuildRequires:  autoconf automake libtool

# The client side, i.e. shared libs and virsh are in a subpackage
Requires: %{name}-client = %{version}-%{release}

# Used by many of the drivers, so turn it on whenever the
# daemon is present
%if %{with_libvirtd}
Requires: bridge-utils
%endif
%if %{with_network}
Requires: dnsmasq >= 2.41
Requires: iptables
%endif
%if %{with_nwfilter}
Requires: ebtables
Requires: iptables
Requires: iptables-ipv6
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
BuildRequires: readline-devel
BuildRequires: ncurses-devel
BuildRequires: gettext
BuildRequires: gnutls-devel
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
%if %{with_avahi}
BuildRequires: avahi-devel
%endif
%if %{with_selinux}
BuildRequires: libselinux-devel
%endif
%if %{with_network}
BuildRequires: dnsmasq >= 2.41
%endif
BuildRequires: bridge-utils
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
BuildRequires: libcurl-devel
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
%patch0 -p1
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch5 -p1
%patch6 -p1
%patch7 -p1
%patch8 -p1
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
%patch209 -p1
%patch210 -p1
%patch211 -p1
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
%patch226 -p1
%patch227 -p1

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
           --with-qemu-user=%{qemu_user} \
           --with-qemu-group=%{qemu_group} \
           --with-init-script=redhat \
           --with-remote-pid-file=%{_localstatedir}/run/libvirtd.pid
make
gzip -9 ChangeLog

%install
rm -fr %{buildroot}

%makeinstall
for i in domain-events/events-c dominfo domsuspend hellolibvirt python xml/nwfilter
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

%if %{with_libvirtd}
chmod 0644 $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/libvirtd
%endif

%clean
rm -fr %{buildroot}

%check
cd tests
# These 3 tests don't current work in a mock build root
for i in nodeinfotest daemon-conf seclabeltest
do
  rm -f $i
  echo -e "#!/bin/sh\nexit 0" > $i
  chmod +x $i
done
# The test applied by patch need to be made executable
chmod +x virsh-schedinfo

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
%endif

%if %{with_cgconfig}
if [ "$1" = "1" ]; then
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
    level=$(/sbin/runlevel | /bin/cut -d ' ' -f 2)
    if /sbin/chkconfig --list libvirt-guests | /bin/grep -q $level:on ; then
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
%config(noreplace) %{_sysconfdir}/sysconfig/libvirtd
%config(noreplace) %{_sysconfdir}/libvirt/libvirtd.conf
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
%dir %attr(0755, root, root) %{_localstatedir}/lib/libvirt/dnsmasq/
%endif
%if %{with_network}
%dir %{_localstatedir}/run/libvirt/network/
%dir %attr(0700, root, root) %{_localstatedir}/lib/libvirt/network/
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

%if %{with_xen_proxy}
%attr(4755, root, root) %{_libexecdir}/libvirt_proxy
%endif

%if %{with_lxc}
%attr(0755, root, root) %{_libexecdir}/libvirt_lxc
%endif

%attr(0755, root, root) %{_libexecdir}/libvirt_parthelper
%attr(0755, root, root) %{_sbindir}/libvirtd

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
%doc examples/xml

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
* Wed Mar 16 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.1-27.el6_0.5
- Properly report error in virConnectDomainXMLToNative (CVE-2011-1146)

* Mon Mar 14 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.1-27.el6_0.4
- Add missing checks for read-only connections (CVE-2011-1146)

* Wed Jan 26 2011 Jiri Denemark <jdenemar@redhat.com> - 0.8.1-27.el6_0.3
- Remove patches not suitable for proper Z-stream:
    - Export host information through SMBIOS to guests (rhbz#652678)
    - Support forcing a CDROM eject (rhbz#658147)
- Plug several memory leaks (rhbz#672549)
- Avoid memory overhead of matchpathcon (rhbz#672554)
- Do not start libvirt-guests if that service is off (rhbz#668694)

* Fri Dec 10 2010 Jiri Denemark <jdenemar@redhat.com> - 0.8.1-27.el6_0.2
- spec file cleanups (rhbz#662045)
- Fix deadlock on concurrent multiple bidirectional migration (rhbz#662043)
- Fix off-by-one error in clock-variable (rhbz#662046)
- Export host information through SMBIOS to guests (rhbz#652678)
- Ensure device is deleted from guest after unplug (rhbz#662041)
- Distinguish between QEMU domain shutdown and crash (rhbz#662042)

* Mon Nov 29 2010 Jiri Denemark <jdenemar@redhat.com> - 0.8.1-27.el6_0.1
- Fix JSON migrate_set_downtime command (rhbz#658143)
- Make SASL work over UNIX domain sockets (rhbz#658144)
- Let qemu group look below /var/lib/libvirt/qemu/ (rhbz#656972)
- Fix save/restore on root_squashed NFS (rhbz#656355)
- Fix race on multiple migration (rhbz#658141)
- Export host information through SMBIOS to guests (rhbz#652678)
- Support forcing a CDROM eject (rhbz#658147)

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
