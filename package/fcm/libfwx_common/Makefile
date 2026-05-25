
include $(TOPDIR)/rules.mk

PKG_NAME:=libfwx_common
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/libfwx_common
  SECTION:=Base system
  CATEGORY:=Base system
  DEPENDS:=+libuci +libjson-c
  TITLE:=fwx common lib
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -rf ./src/* $(PKG_BUILD_DIR)
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/ \
	CC="$(TARGET_CROSS)gcc" \
	CFLAGS="$(TARGET_CFLAGS)" \
	LIBS="$(TARGET_LDFLAGS) -lm -luci -ljson-c" \
	all
endef	


define Build/Compile/Default

endef

define Package/$(PKG_NAME)/description
  fwx common lib
endef


define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libfwx_common.so $(1)/usr/lib
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/*.h $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libfwx_common.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))

