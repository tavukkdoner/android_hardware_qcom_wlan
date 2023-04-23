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

struct nan_pairing_peer_info*
nan_pairing_add_peer_to_list(struct wpa_secure_nan *secure_nan, u8 *mac)
{
    struct nan_pairing_peer_info *entry, *mentry = NULL;

    list_for_each_entry(entry, &secure_nan->peers, list) {

       if (memcmp(entry->bssid, mac, ETH_ALEN) == 0) {
           if (entry->is_paired) {
               ALOGV(" %s :Peer already paired: ADDR=" MACSTR,
                     __FUNCTION__, MAC2STR(mac));
           } else {
               ALOGV(" %s :Add peer req for existing peer: ADDR=" MACSTR,
                     __FUNCTION__, MAC2STR(mac));
           }
           entry->pairing_instance_id = secure_nan->pairing_id++;
           wpa_pasn_reset(&entry->pasn);
           return entry;
       }
    }

    mentry = (struct nan_pairing_peer_info *)malloc(sizeof(*entry));
    if (!mentry) {
        ALOGE("%s: peer entry malloc failed", __FUNCTION__);
        return NULL;
    }

    memset((char *)mentry, 0, sizeof(*entry));
    memcpy(mentry->bssid, mac, ETH_ALEN);
    mentry->pairing_instance_id = secure_nan->pairing_id++;

    mentry->pasn.cb_ctx = secure_nan->cb_ctx;
    wpa_pasn_reset(&mentry->pasn);
    add_to_list(&mentry->list, &secure_nan->peers);
    return mentry;
}

struct nan_pairing_peer_info*
nan_pairing_get_peer_from_list(struct wpa_secure_nan *secure_nan, u8 *mac)
{
    struct nan_pairing_peer_info *entry;

    list_for_each_entry(entry, &secure_nan->peers, list) {
       if (memcmp(entry->bssid, mac, ETH_ALEN) == 0)
                  return entry;
    }
    return NULL;
}

struct nan_pairing_peer_info*
nan_pairing_get_peer_from_id(struct wpa_secure_nan *secure_nan, u32 pairing_id)
{
    struct nan_pairing_peer_info *entry;

    list_for_each_entry(entry, &secure_nan->peers, list) {
       if (entry->pairing_instance_id == pairing_id)
           return entry;
    }
    return NULL;
}

void nan_pairing_delete_list(struct wpa_secure_nan *secure_nan)
{
    struct nan_pairing_peer_info *entry, *tmp;

    list_for_each_entry_safe(entry, tmp, &secure_nan->peers, list) {
         del_from_list(&entry->list);

         if (entry->pasn.extra_ies)
             free((u8 *)entry->pasn.extra_ies);

         wpa_pasn_reset(&entry->pasn);

         if (entry->frame)
             free(entry->frame);

         free(entry);
    }
}

void nan_pairing_delete_peer_from_list(struct wpa_secure_nan *secure_nan,
                                       u8 *mac)
{
    struct nan_pairing_peer_info *entry, *tmp;

    list_for_each_entry_safe(entry, tmp, &secure_nan->peers, list) {
       if (memcmp(entry->bssid, mac, ETH_ALEN) == 0) {
                 del_from_list(&entry->list);

                 if (entry->pasn.extra_ies)
                     free((u8 *)entry->pasn.extra_ies);

                 wpa_pasn_reset(&entry->pasn);

                 if (entry->frame)
                     free(entry->frame);

                 free(entry);
                 return;
       }
    }
}

static int nan_send_nl_msg_event_sock(hal_info *info, struct nl_msg *msg)
{
    int res = 0;
    struct nl_cb * cb = NULL;

    if (!info->event_sock) {
        ALOGE("event socket is null");
        return -1;
    }

    /* send message */
    res = nl_send_auto_complete(info->event_sock, msg);
    if (res < 0)
           return res;

    cb = nl_socket_get_cb(info->event_sock);

    /* err is populated as part of finish_handler */
    while (res > 0)
        res = nl_recvmsgs(info->event_sock, cb);

    nl_cb_put(cb);
    return res;
}

static int nan_pairing_register_pasn_auth_frames(wifi_interface_handle iface)
{
    u32 idx;
    struct nl_msg * msg;
    wifi_handle wifiHandle = getWifiHandle(iface);
    hal_info *info = getHalInfo(wifiHandle);

    msg = nlmsg_alloc();
    if (!msg) {
        ALOGE("%s: nlmsg malloc failed", __FUNCTION__);
        return -1;
    }

    genlmsg_put(msg, 0, 0, info->nl80211_family_id, 0, 0,
                NL80211_CMD_REGISTER_FRAME, 0);

    idx = if_nametoindex(DEFAULT_NAN_IFACE);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, idx);

    /* wlan type:mgmt, wlan subtype: auth */
    u16 type = (WLAN_FC_TYPE_MGMT << 2) | (WLAN_FC_STYPE_AUTH << 4);
    /* register for PASN Authentication frames */
    const u8 pasn_auth_match[2] = {7,0};
    nla_put_u16(msg, NL80211_ATTR_FRAME_TYPE, type);
    nla_put(msg, NL80211_ATTR_FRAME_MATCH, 2, pasn_auth_match);

    nan_send_nl_msg_event_sock(info, msg);

    if (msg)
        nlmsg_free(msg);

    return 0;
}

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

    if (nan_pairing_register_pasn_auth_frames(iface)) {
        ALOGE("Secure NAN Register PASN auth failed");
        return -1;
    }
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
    nan_pairing_delete_list(info->secure_nan);

    os_free(info->secure_nan);
    info->secure_nan = NULL;
    return 0;
}

#else  /* WPA_PASN_LIB */

struct nan_pairing_peer_info*
nan_pairing_add_peer_to_list(struct wpa_secure_nan *secure_nan, u8 *mac)
{
   return NULL;
}

struct nan_pairing_peer_info*
nan_pairing_get_peer_from_list(struct wpa_secure_nan *secure_nan, u8 *mac)
{
    return NULL;
}

struct nan_pairing_peer_info*
nan_pairing_get_peer_from_id(struct wpa_secure_nan *secure_nan, u32 pairing_id)
{
  return NULL;
}

void nan_pairing_delete_list(struct wpa_secure_nan *secure_nan)
{
   return;
}

void nan_pairing_delete_peer_from_list(struct wpa_secure_nan *secure_nan,
                                       u8 *mac)
{
   return;
}

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
