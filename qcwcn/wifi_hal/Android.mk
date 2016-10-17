# Copyright (C) 2011 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

LOCAL_PATH := $(call my-dir)

NAN_VENDOR_AIDL=y

# Control APIs used by clients to communicate with HAL.
# ============================================================
include $(CLEAR_VARS)

LOCAL_CFLAGS := -Wno-unused-parameter
LOCAL_CFLAGS += -Wall -Werror
LOCAL_MODULE := libwifi-hal-ctrl
LOCAL_VENDOR_MODULE := true
LOCAL_C_INCLUDES := $(LOCAL_PATH)/wifi_hal_ctrl
LOCAL_SRC_FILES := wifi_hal_ctrl/wifi_hal_ctrl.c
LOCAL_HEADER_LIBRARIES := libcutils_headers
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libwifi-hal-ctrl_headers
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/wifi_hal_ctrl
LOCAL_HEADER_LIBRARIES := libcutils_headers
include $(BUILD_HEADER_LIBRARY)

# Make the HAL library
# ============================================================
include $(CLEAR_VARS)

NAN_PAIRING=y

LOCAL_CFLAGS := -Wno-unused-parameter
ifeq ($(TARGET_BUILD_VARIANT),eng)
LOCAL_CFLAGS += "-DLOG_NDEBUG=0"
endif

ifneq ($(TARGET_USES_AOSP_FOR_WLAN), true)
LOCAL_CFLAGS += -DWCNSS_QTI_AOSP
endif

ifeq ($(strip $(CONFIG_MAC_PRIVACY_LOGGING)),true)
LOCAL_CFLAGS += -DCONFIG_MAC_PRIVACY_LOGGING
endif

ifeq ($(NAN_VENDOR_AIDL),y)
LOCAL_CFLAGS += -DCONFIG_NAN_VENDOR_AIDL
endif

# gscan.cpp: address of array 'cached_results[i].results' will always evaluate to 'true'
LOCAL_CLANG_CFLAGS := -Wno-pointer-bool-conversion

LOCAL_CFLAGS += -Wall -Werror

ifeq ($(NAN_PAIRING),y)
ifeq ($(CONFIG_PASN),y)
LOCAL_CFLAGS += -DWPA_PASN_LIB
LOCAL_CFLAGS += -DCONFIG_PASN
LOCAL_CFLAGS += -DCONFIG_PTKSA_CACHE
ifeq ($(CONFIG_SAE),y)
LOCAL_CFLAGS += -DCONFIG_SAE
endif
ifeq ($(CONFIG_FILS),y)
LOCAL_CFLAGS += -DCONFIG_FILS
endif
ifeq ($(CONFIG_IEEE80211R),y)
LOCAL_CFLAGS += -DCONFIG_IEEE80211R
endif
ifeq ($(CONFIG_TESTING_OPTIONS),y)
LOCAL_CFLAGS += -DCONFIG_TESTING_OPTIONS
endif
ifeq ($(CONFIG_IEEE8021X_EAPOL),y)
LOCAL_CFLAGS += -DIEEE8021X_EAPOL
endif
ifeq ($(CONFIG_NO_RANDOM_POOL),y)
LOCAL_CFLAGS += -DCONFIG_NO_RANDOM_POOL
endif
endif
endif

ifdef WIFI_DRIVER_STATE_CTRL_PARAM
LOCAL_CFLAGS += -DWIFI_DRIVER_STATE_CTRL_PARAM=\"$(WIFI_DRIVER_STATE_CTRL_PARAM)\"
ifdef WIFI_DRIVER_STATE_ON
LOCAL_CFLAGS += -DWIFI_DRIVER_STATE_ON=\"$(WIFI_DRIVER_STATE_ON)\"
endif
endif

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH) \
	$(LOCAL_PATH)/vendor_nan \
	external/libnl/include \
	$(call include-path-for, libhardware_legacy)/hardware_legacy \
	external/wpa_supplicant_8/src/drivers \
	external/wpa_supplicant_8/src \
	external/wpa_supplicant_8/src/utils \

LOCAL_C_INCLUDES += \
	external/boringssl/include \
	external/boringssl/src/crypto/digest \
	external/boringssl/src/crypto/evp/

LOCAL_SRC_FILES := \
	list.cpp \
	wifi_hal.cpp \
	common.cpp \
	cpp_bindings.cpp \
	llstats.cpp \
	gscan.cpp \
	gscan_event_handler.cpp \
	rtt.cpp \
	ifaceeventhandler.cpp \
	tdls.cpp \
	nan.cpp \
	nan_ind.cpp \
	nan_req.cpp \
	nan_rsp.cpp \
	wificonfig.cpp \
	wifilogger.cpp \
	wifilogger_diag.cpp \
	ring_buffer.cpp \
	rb_wrapper.cpp \
	rssi_monitor.cpp \
	roam.cpp \
	radio_mode.cpp \
	tcp_params_update.cpp \
	wifihal_vendor.cpp \
	nan_pairing.cpp \
	nan_pairing_responder.cpp \
	nan_pairing_initiator.cpp

ifeq ($(NAN_VENDOR_AIDL),y)
LOCAL_SRC_FILES += \
	vendor_nan/vendor_nan.cpp
endif

LOCAL_MODULE := libwifi-hal-qcom
LOCAL_VENDOR_MODULE := true
LOCAL_CLANG := true
LOCAL_SHARED_LIBRARIES += libnetutils liblog libcld80211
LOCAL_SHARED_LIBRARIES += libcrypto
LOCAL_SHARED_LIBRARIES += libcutils
ifeq ($(NAN_PAIRING),y)
ifeq ($(CONFIG_PASN),y)
LOCAL_SHARED_LIBRARIES += libpasn
endif
endif

ifneq ($(wildcard external/libnl),)
LOCAL_SHARED_LIBRARIES += libnl
LOCAL_C_INCLUDES += external/libnl/include
else
LOCAL_SHARED_LIBRARIES += libnl_2
LOCAL_C_INCLUDES += external/libnl-headers
endif

LOCAL_HEADER_LIBRARIES := libcutils_headers libutils_headers libwifi-hal-ctrl_headers libcld80211_headers
LOCAL_SANITIZE := cfi signed-integer-overflow unsigned-integer-overflow

ifeq ($(TARGET_SUPPORTS_WEARABLES), true)
LOCAL_CFLAGS += -DTARGET_SUPPORTS_WEARABLES
endif

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_REQUIRED_MODULES :=

LOCAL_CFLAGS += -Wno-unused-parameter -Wall -Werror
LOCAL_CPPFLAGS += -Wno-conversion-null
ifeq ($(TARGET_BUILD_VARIANT),userdebug)
LOCAL_CFLAGS += "-DLOG_NDEBUG=0"
endif

ifeq ($(strip $(CONFIG_MAC_PRIVACY_LOGGING)),true)
LOCAL_CFLAGS += -DCONFIG_MAC_PRIVACY_LOGGING
endif

ifeq ($(NAN_VENDOR_AIDL),y)
LOCAL_CFLAGS += -DCONFIG_NAN_VENDOR_AIDL
endif

ifeq ($(NAN_PAIRING),y)
ifeq ($(CONFIG_PASN),y)
LOCAL_CFLAGS += -DWPA_PASN_LIB
LOCAL_CFLAGS += -DCONFIG_PASN
LOCAL_CFLAGS += -DCONFIG_PTKSA_CACHE
ifeq ($(CONFIG_SAE),y)
LOCAL_CFLAGS += -DCONFIG_SAE
endif
ifeq ($(CONFIG_FILS),y)
LOCAL_CFLAGS += -DCONFIG_FILS
endif
ifeq ($(CONFIG_IEEE80211R),y)
LOCAL_CFLAGS += -DCONFIG_IEEE80211R
endif
ifeq ($(CONFIG_TESTING_OPTIONS),y)
LOCAL_CFLAGS += -DCONFIG_TESTING_OPTIONS
endif
ifeq ($(CONFIG_IEEE8021X_EAPOL),y)
LOCAL_CFLAGS += -DIEEE8021X_EAPOL
endif
ifeq ($(CONFIG_NO_RANDOM_POOL),y)
LOCAL_CFLAGS += -DCONFIG_NO_RANDOM_POOL
endif
endif
endif

# gscan.cpp: address of array 'cached_results[i].results' will always evaluate to 'true'
LOCAL_CLANG_CFLAGS := -Wno-pointer-bool-conversion

ifdef WIFI_DRIVER_STATE_CTRL_PARAM
LOCAL_CFLAGS += -DWIFI_DRIVER_STATE_CTRL_PARAM=\"$(WIFI_DRIVER_STATE_CTRL_PARAM)\"
ifdef WIFI_DRIVER_STATE_ON
LOCAL_CFLAGS += -DWIFI_DRIVER_STATE_ON=\"$(WIFI_DRIVER_STATE_ON)\"
endif
endif

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH) \
	$(LOCAL_PATH)/vendor_nan \
	external/libnl/include \
	$(call include-path-for, libhardware_legacy)/hardware_legacy \
	external/wpa_supplicant_8/src/drivers \
	external/wpa_supplicant_8/src \
	external/wpa_supplicant_8/src/utils \

LOCAL_C_INCLUDES += \
	external/boringssl/include \
	external/boringssl/src/crypto/digest \
	external/boringssl/src/crypto/evp/

LOCAL_SRC_FILES := \
	list.cpp \
	wifi_hal.cpp \
	common.cpp \
	cpp_bindings.cpp \
	llstats.cpp \
	gscan.cpp \
	gscan_event_handler.cpp \
	rtt.cpp \
	ifaceeventhandler.cpp \
	tdls.cpp \
	nan.cpp \
	nan_ind.cpp \
	nan_req.cpp \
	nan_rsp.cpp \
	wificonfig.cpp \
	wifilogger.cpp \
	wifilogger_diag.cpp \
	ring_buffer.cpp \
	rb_wrapper.cpp \
	rssi_monitor.cpp \
	roam.cpp \
	radio_mode.cpp \
	tcp_params_update.cpp \
	wifihal_vendor.cpp \
	nan_pairing.cpp \
	nan_pairing_responder.cpp \
	nan_pairing_initiator.cpp

ifeq ($(NAN_VENDOR_AIDL),y)
LOCAL_SRC_FILES += \
	vendor_nan/vendor_nan.cpp
endif

LOCAL_CFLAGS += -Wall -Werror
LOCAL_MODULE := libwifi-hal-qcom
LOCAL_VENDOR_MODULE := true
LOCAL_CLANG := true
LOCAL_SHARED_LIBRARIES += libnetutils liblog
LOCAL_SHARED_LIBRARIES += libdl libcld80211
LOCAL_SHARED_LIBRARIES += libwifi-hal-ctrl
LOCAL_SHARED_LIBRARIES += libcrypto
LOCAL_SHARED_LIBRARIES += libcutils
ifeq ($(NAN_PAIRING),y)
ifeq ($(CONFIG_PASN),y)
LOCAL_SHARED_LIBRARIES += libpasn
endif
endif

ifneq ($(wildcard external/libnl),)
LOCAL_SHARED_LIBRARIES += libnl
LOCAL_C_INCLUDES += external/libnl/include
else
LOCAL_SHARED_LIBRARIES += libnl_2
LOCAL_C_INCLUDES += external/libnl-headers
endif

LOCAL_HEADER_LIBRARIES := libcutils_headers libutils_headers libwifi-hal-ctrl_headers libcld80211_headers
LOCAL_SANITIZE := cfi integer_overflow

ifeq ($(TARGET_SUPPORTS_WEARABLES), true)
LOCAL_CFLAGS += -DTARGET_SUPPORTS_WEARABLES
endif

include $(BUILD_SHARED_LIBRARY)
