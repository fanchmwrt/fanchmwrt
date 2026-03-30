#
# Copyright (C) 2008-2014 The LuCI Team <luci@lists.subsignal.org>
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk

LUCI_TITLE:=FanchmWrt Theme (default)
LUCI_DEPENDS:=+luci-base +@LUCI_LANG_zh_Hans +luci-i18n-base-zh-cn
PKG_LICENSE:=Apache-2.0

define Package/luci-theme-fanchmwrt/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	uci -q delete luci.themes.Bootstrap
	uci -q delete luci.themes.BootstrapDark
	uci -q delete luci.themes.BootstrapLight
	uci commit luci
}
endef


include $(TOPDIR)/feeds/luci/luci.mk
# call BuildPackage - OpenWrt buildroot signature
