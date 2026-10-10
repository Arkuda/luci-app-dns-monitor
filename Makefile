# SPDX-License-Identifier: ISC
include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-dns-monitor
PKG_VERSION:=1.0.0
PKG_RELEASE:=2
PKG_PO_VERSION:=$(PKG_VERSION)-r$(PKG_RELEASE)
PKG_LICENSE:=ISC
PKG_BUILD_PARALLEL:=1

LUCI_NAME:=luci-app-dns-monitor
LUCI_TITLE:=LuCI per-client DNS monitor
LUCI_DESCRIPTION:=Explicitly controlled, RAM-only dnsmasq query monitoring with bounded history and optional ruantiblock user-list editing.
# Custom package: do not attribute maintenance or its source URL to LuCI upstream.
LUCI_MAINTAINER:=
LUCI_URL:=
# A small native collector keeps per-query processing allocation-free.
LUCI_PKGARCH:=
LUCI_DEPENDS:=+luci-base +dnsmasq +libubus +libubox +libjson-c +rpcd-mod-ucode +ucode-mod-fs +ucode-mod-uci +flock +jsonfilter +coreutils-stat

define Package/luci-app-dns-monitor/conffiles
/etc/config/dns-monitor
endef

define Build/Prepare/luci-app-dns-monitor
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/root/usr/share/licenses/$(PKG_NAME)
	$(INSTALL_DATA) ./LICENSE $(PKG_BUILD_DIR)/root/usr/share/licenses/$(PKG_NAME)/LICENSE
	find $(PKG_BUILD_DIR)/root $(PKG_BUILD_DIR)/htdocs -type d -exec chmod 0755 {} +
	find $(PKG_BUILD_DIR)/root $(PKG_BUILD_DIR)/htdocs -type f -exec chmod 0644 {} +
	chmod 0755 $(PKG_BUILD_DIR)/root/etc/init.d/dns-monitor
	chmod 0755 $(PKG_BUILD_DIR)/root/usr/libexec/dns-monitor-lifecycle
endef

define Package/luci-app-dns-monitor/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
rm -f /tmp/luci-indexcache.*
/etc/init.d/dns-monitor enable
/etc/init.d/dns-monitor start
/etc/init.d/rpcd reload
exit 0
endef

define Package/luci-app-dns-monitor/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/dns-monitor stop || exit 1
/usr/libexec/dns-monitor-lifecycle recover || exit 1
/etc/init.d/dns-monitor disable
exit 0
endef
include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
