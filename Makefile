include theos/makefiles/common.mk

TWEAK_NAME = CloakJB
CloakJB_FILES = Tweak.xm mach_hook/mach_hook.c

include $(THEOS_MAKE_PATH)/tweak.mk
