include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=shortcut-fe
PKG_VERSION:=2019.02.27~c7dd8173
PKG_RELEASE:=7
PKG_LICENSE:=ISC
PKG_FILE_DEPENDS:=$(CURDIR)/src
PKG_BUILD_PARALLEL:=1
PKG_BUILD_DEPENDS:=fwx

include $(INCLUDE_DIR)/package.mk

define KernelPackage/shortcut-fe
  SUBMENU:=Network Support
  TITLE:=SFE with connection manager
  DEPENDS:=@IPV6 +kmod-nf-conntrack +kmod-fwx
  AUTOLOAD:=$(call AutoLoad,09,shortcut-fe shortcut-fe-ipv6 shortcut-fe-cm)
  KCONFIG:= \
	CONFIG_SHORTCUT_FE=y \
	CONFIG_NF_CONNTRACK_EVENTS=y \
	CONFIG_NF_CONNTRACK_MARK=y \
	CONFIG_NF_CONNTRACK_TIMEOUT=y
  FILES:= \
	$(PKG_BUILD_DIR)/shortcut-fe.ko \
	$(PKG_BUILD_DIR)/shortcut-fe-ipv6.ko \
	$(PKG_BUILD_DIR)/shortcut-fe-cm.ko
endef

define KernelPackage/shortcut-fe/description
	shortcut fe	
endef

define KernelPackage/shortcut-fe/conffiles
/etc/config/fastnat
endef

define KernelPackage/shortcut-fe/install
	$(INSTALL_DIR) $(1)/etc/config $(1)/etc/init.d
	$(INSTALL_CONF) ./files/fastnat.config $(1)/etc/config/fastnat
	$(INSTALL_BIN) ./files/fastnat.init $(1)/etc/init.d/fastnat
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./src/. $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" SFE_SUPPORT_IPV6=y \
		FWX_INCLUDE_DIR="$(STAGING_DIR)/usr/include/fwx" modules
endef

$(eval $(call KernelPackage,shortcut-fe))
