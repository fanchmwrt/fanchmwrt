
include $(TOPDIR)/rules.mk

PKG_NAME:=fwxd
PKG_VERSION:=1.0.1
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
include $(INCLUDE_DIR)/package.mk

TARGET_CFLAGS +=-Werror=implicit-function-declaration
define Package/fwxd
  SECTION:=Base system
  CATEGORY:=Base system
  DEPENDS:=+libubox +libubus  +libuci +libpthread +libjson-c +libblobmsg-json +libuci-lua +libfwx_common
  TITLE:=Fanchm fwx application
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -rf ./src/* $(PKG_BUILD_DIR)
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/ \
	CC="$(TARGET_CROSS)gcc" \
	CFLAGS="$(TARGET_CFLAGS)" \
	LIBS="$(TARGET_LDFLAGS) -lm -lpthread -lubox -luci -lubus -ljson-c -lblobmsg_json -lfwx_common" \
	all
endef	


define Build/Compile/Default

endef

define Package/fwxd/description
  fwxd app
endef


define Package/fwxd/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/fwxd
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(CP) ./files/*.cfg $(1)/etc/fwxd/ 
	$(INSTALL_BIN) ./files/uci-defaults/* $(1)/etc/uci-defaults/
	$(INSTALL_BIN) ./files/fwx.init $(1)/etc/init.d/fwx
	$(INSTALL_BIN) ./files/gen_class.sh $(1)/usr/bin
	$(INSTALL_BIN) ./files/fwx_cli.sh $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/fwxd $(1)/usr/bin
	$(INSTALL_BIN) ./files/fwx-dump.sh $(1)/usr/bin/fwx-dump
	$(INSTALL_BIN) ./files/rule_manager.lua $(1)/usr/bin/rule_manager
	$(INSTALL_DATA) ./files/appfilter.config $(1)/etc/config/appfilter
	$(INSTALL_DATA) ./files/macfilter.config $(1)/etc/config/macfilter
	$(INSTALL_DATA) ./files/user_info.config $(1)/etc/config/user_info
	$(INSTALL_DATA) ./files/fwx.config $(1)/etc/config/fwx
	$(INSTALL_DATA) ./files/macfilter_whitelist.config $(1)/etc/config/macfilter_whitelist
	$(INSTALL_DATA) ./files/appfilter_whitelist.config $(1)/etc/config/appfilter_whitelist
	$(INSTALL_DATA) ./files/fwx.version $(1)/etc/fwx_version

endef


$(eval $(call BuildPackage,fwxd))

