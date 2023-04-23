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

/* NAN Identity key lifetime in seconds */
static const int NIKLifetime = 43200;
/* NAN group key lifetime in seconds */
static const int GrpKeyLifetime = 43200;

void nan_pairing_set_nik_nira(struct wpa_secure_nan *secure_nan)
{
    int ret;
    struct nanIDkey *nik;
    u8 data[NIR_STR_LEN + NAN_IDENTITY_NONCE_LEN + ETH_ALEN];
    u8 tag[32];

    if (!secure_nan || !secure_nan->dev_nik) {
        ALOGE("%s: Secure NAN device NIK Null ", __FUNCTION__);
        return;
    }

    nik = secure_nan->dev_nik;

    ret = random_get_bytes(nik->nik_data, NAN_IDENTITY_KEY_LEN);
    if (ret < 0) {
        ALOGE("%s: Get random NIK data Failed, err = %d", __FUNCTION__, ret);
        return;
    }

    ret = random_get_bytes(nik->nira_nonce, NAN_IDENTITY_NONCE_LEN);
    if (ret < 0) {
        ALOGE("%s: Get random NIRA nonce Failed, err = %d", __FUNCTION__, ret);
        return;
    }

    os_memset(data, 0, sizeof(data));
    os_memset(tag, 0, sizeof(tag));
    os_memset(nik->nira_tag, 0, NAN_IDENTITY_TAG_LEN);

    os_memcpy(data, "NIR", NIR_STR_LEN);
    os_memcpy(&data[NIR_STR_LEN], secure_nan->own_addr, ETH_ALEN);
    os_memcpy(&data[NIR_STR_LEN + ETH_ALEN], nik->nira_nonce,
              NAN_IDENTITY_NONCE_LEN);

    ALOGD("NAN PASN:" MACSTR, MAC2STR(secure_nan->own_addr));
    ret = hmac_sha256(nik->nik_data, NAN_IDENTITY_KEY_LEN, data, sizeof(data), tag);
    if (ret < 0) {
        ALOGE("%s: Could not derive NIRA tag, err = %d", __FUNCTION__, ret);
        return;
    }
    os_memcpy(nik->nira_tag, tag, NAN_IDENTITY_TAG_LEN);

    nik->nik_len = NAN_IDENTITY_KEY_LEN;
    nik->nira_nonce_len = NAN_IDENTITY_NONCE_LEN;
    nik->nira_tag_len = NAN_IDENTITY_TAG_LEN;
}

unsigned int nan_pairing_get_nik_lifetime(struct nanIDkey *nik)
{
    struct os_reltime now;
    os_get_reltime(&now);

    if (nik && nik->expiration > now.sec)
        return (nik->expiration - now.sec);

    return 0;
}

static struct nanIDkey * nan_pairing_nik_init(void)
{
    struct nanIDkey *nik = (struct nanIDkey *)os_zalloc(sizeof(struct nanIDkey));
    if (!nik) {
        ALOGE("NAN NIK: Init failed");
        return NULL;
    }
    return nik;
}

static void nan_pairing_nik_deinit(struct nanIDkey *nik)
{
    os_free(nik);
    ALOGD("NAN NIK: De-Initialize");
    return;
}

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

    secure_nan->dev_nik = nan_pairing_nik_init();
    if (!secure_nan->dev_nik)
        return -1;

    secure_nan->initiator_pmksa = nan_pairing_initiator_pmksa_cache_init();
    if (!secure_nan->initiator_pmksa) {
        ALOGE("Secure NAN Initiator PMKSA cache init failed");
        return -1;
    }

    secure_nan->responder_pmksa = nan_pairing_responder_pmksa_cache_init();
    if (!secure_nan->responder_pmksa) {
        ALOGE("Secure NAN Responder PMKSA cache init failed");
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

    if (info->secure_nan->dev_nik)
        nan_pairing_nik_deinit(info->secure_nan->dev_nik);

    nan_pairing_initiator_pmksa_cache_deinit(info->secure_nan->initiator_pmksa);
    nan_pairing_responder_pmksa_cache_deinit(info->secure_nan->responder_pmksa);

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
