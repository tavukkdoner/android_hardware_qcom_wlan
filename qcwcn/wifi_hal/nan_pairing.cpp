/*
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc.All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "wifihal_list.h"
#include "wifi_hal.h"
#include "nan_i.h"
#include "nancommand.h"
#include "common.h"
#include "cpp_bindings.h"
#include <utils/Log.h>
#include <errno.h>

#ifdef WPA_PASN_LIB

int secure_nan_init(wifi_interface_handle iface)
{
    struct wpa_secure_nan *secure_nan = NULL;
    wifi_handle wifiHandle = getWifiHandle(iface);
    hal_info *info = getHalInfo(wifiHandle);

    if (info->secure_nan) {
        ALOGE("Secure NAN Already initialized");
        return 0;
    }

    secure_nan = (struct wpa_secure_nan *)os_zalloc(sizeof(*secure_nan));

    secure_nan->cb_ctx = wifiHandle;
    secure_nan->cb_iface_ctx = iface;
    secure_nan->ptksa = ptksa_cache_init();
    if (!secure_nan->ptksa) {
        ALOGE("Secure NAN PTKSA init failed");
        return -1;
    }

    info->secure_nan = secure_nan;
    //! Initailise peers list
    INITIALISE_LIST(&secure_nan->peers);

    return 0;
}

int secure_nan_deinit(hal_info *info)
{
    if(!info->secure_nan) {
       ALOGE("Secure NAN == NULL");
       return -1;
    }

    if (info->secure_nan->ptksa)
        ptksa_cache_deinit(info->secure_nan->ptksa);

    os_free(info->secure_nan);
    info->secure_nan = NULL;
    return 0;
}

#else  /* WPA_PASN_LIB */

int secure_nan_init(wifi_interface_handle iface)
{
    ALOGE("Secure NAN init not supported");
    return -1;
}

int secure_nan_deinit(hal_info *info)
{
    ALOGE("Secure NAN deinit not supported");
    return -1;
}

#endif /* WPA_PASN_LIB */
