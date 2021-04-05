#
# Copyright (C) 2021 Starship Troopers (C), Aleksandr Cherviakov
# 
# OpenWRT xt_fset package build Makefile for OpenWRT
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=xt_fset
PKG_VERSION:=0.1
PKG_RELEASE:=1
PKG_LICENSE:=BSD-2-Clause
PKG_BUILD_DEPENDS:=iptables
PKG_MAINTAINER:=Aleksandr Cherviakov <wormixx@gmail.com>
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel-defaults.mk

MAKE_FLAGS += \
	KDIR="$(LINUX_DIR)" \
	$(KERNEL_MAKE_FLAGS) \
	SUBDIRS="$(PKG_BUILD_DIR)"

define KernelPackage/xt_fset/description
  Iptables extension and kernel module for manipulating ipsets with IP address grabbed from customizable offset in network packet
endef

define Build/Install
	true
endef

define KernelPackage/xt_fset/install
	$(INSTALL_DIR) $(1)/usr/lib/iptables
	$(CP) \
		$(PKG_BUILD_DIR)/libxt_FSET.so \
		$(1)/usr/lib/iptables/ ;
endef

define KernelPackage/xt_fset
    CATEGORY:=Network
    SUBMENU:=Firewall
    TITLE:=xt_FSET netfilter module
    DEPENDS:=+kmod-ipt-core +kmod-ipt-ipset +libc +libgcc
    FILES:=$(PKG_BUILD_DIR)/xt_FSET.$(LINUX_KMOD_SUFFIX)
    AUTOLOAD:=$(call AutoProbe,xt_FSET)
endef

$(eval $(call KernelPackage,xt_fset))
