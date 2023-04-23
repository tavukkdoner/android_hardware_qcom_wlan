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
#define NAN_PAIRING_SSID "516F9A010000"

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
    mentry->pasn.send_mgmt = nan_send_tx_mgmt;
    mentry->pasn.validate_custom_pmkid = nan_pairing_validate_custom_pmkid;
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

         if (entry->passphrase)
             free(entry->passphrase);

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

                 if (entry->passphrase)
                     free(entry->passphrase);

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

/* callback handlers registered for nl message send */
static int error_handler_nan(struct sockaddr_nl *nla, struct nlmsgerr *err,
                         void *arg)
{
    struct sockaddr_nl * tmp;
    int *ret = (int *)arg;
    tmp = nla;
    *ret = err->error;
    ALOGE("%s: Error code:%d (%s)", __func__, *ret, strerror(-(*ret)));
    return NL_STOP;
}

/* callback handlers registered for nl message send */
static int ack_handler_nan(struct nl_msg *msg, void *arg)
{
    int *ret = (int *)arg;
    struct nl_msg * a;

    a = msg;
    *ret = 0;
    return NL_STOP;
}

/* callback handlers registered for nl message send */
static int finish_handler_nan(struct nl_msg *msg, void *arg)
{
  int *ret = (int *)arg;
  struct nl_msg * a;

  a = msg;
  *ret = 0;
  return NL_SKIP;
}

static int nan_send_nl_msg(hal_info *info, struct nl_msg *msg)
{
    int res = 0;
    struct nl_cb * cb = NULL;

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        ALOGE("%s: Callback allocation failed",__func__);
        res = -1;
        goto out;
    }

    if (!info->cmd_sock) {
        ALOGE("%s: Command socket is null",__func__);
        res = -1;
        goto out;
    }

    /* send message */
    res = nl_send_auto_complete(info->cmd_sock, msg);
    if (res < 0) {
        ALOGE("%s: send msg failed. err = %d",__func__, res);
        goto out;
    }

    res = 1;

    nl_cb_err(cb, NL_CB_CUSTOM, error_handler_nan, &res);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler_nan, &res);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler_nan, &res);

    // err is populated as part of finish_handler
    while (res > 0)
        nl_recvmsgs(info->cmd_sock, cb);

out:
    nl_cb_put(cb);
    return res;
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
    if (res < 0) {
           ALOGE("%s: send msg failed. err = %d",__func__, res);
           return res;
    }

    cb = nl_socket_get_cb(info->event_sock);

    /* err is populated as part of finish_handler */
    while (res > 0)
        res = nl_recvmsgs(info->event_sock, cb);

    nl_cb_put(cb);
    return res;
}

int nan_send_tx_mgmt(void *ctx, const u8 *frame_buf, size_t frame_len,
                     int noack, unsigned int freq, unsigned int wait_dur)
{
    wifi_handle handle = (wifi_handle)ctx;
    hal_info *info = getHalInfo(handle);
    struct nl_msg * msg;
    int err = 0, l = 0;
    u32 i, idx;

    msg = nlmsg_alloc();

    if (!msg) {
        ALOGE("%s: Memory allocation failed \n", __FUNCTION__);
        return -1;
    }

    genlmsg_put(msg, 0, 0, info->nl80211_family_id, 0, 0, NL80211_CMD_FRAME, 0);

    idx = if_nametoindex(DEFAULT_NAN_IFACE);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, idx);
    /* Add Frame here */
    nla_put(msg, NL80211_ATTR_FRAME, frame_len, frame_buf);

    err = nan_send_nl_msg(info, msg);

out_free_msg:
    nlmsg_free(msg);
    return err;
}

static u32 wpa_alg_to_cipher_suite(enum wpa_alg alg, size_t key_len)
{
    switch (alg) {
    case WPA_ALG_WEP:
        if (key_len == 5)
            return RSN_CIPHER_SUITE_WEP40;
        return RSN_CIPHER_SUITE_WEP104;
    case WPA_ALG_TKIP:
        return RSN_CIPHER_SUITE_TKIP;
    case WPA_ALG_CCMP:
        return RSN_CIPHER_SUITE_CCMP;
    case WPA_ALG_GCMP:
        return RSN_CIPHER_SUITE_GCMP;
    case WPA_ALG_CCMP_256:
        return RSN_CIPHER_SUITE_CCMP_256;
    case WPA_ALG_GCMP_256:
        return RSN_CIPHER_SUITE_GCMP_256;
    case WPA_ALG_BIP_CMAC_128:
        return RSN_CIPHER_SUITE_AES_128_CMAC;
    case WPA_ALG_BIP_GMAC_128:
        return RSN_CIPHER_SUITE_BIP_GMAC_128;
    case WPA_ALG_BIP_GMAC_256:
        return RSN_CIPHER_SUITE_BIP_GMAC_256;
    case WPA_ALG_BIP_CMAC_256:
        return RSN_CIPHER_SUITE_BIP_CMAC_256;
    case WPA_ALG_SMS4:
        return RSN_CIPHER_SUITE_SMS4;
    case WPA_ALG_KRK:
        return RSN_CIPHER_SUITE_KRK;
    default:
        ALOGI("NAN: Unexpected encryption algorithm %d", alg);
        return 0;
    }
}

static int nan_pairing_set_key(hal_info *info, int alg, const u8 *addr,
                               int key_idx, int set_tx, const u8 *seq,
                               size_t seq_len, const u8 *key, size_t key_len,
                               int key_flag)
{
    int idx;
    u32 suite;
    struct nl_msg *msg;
    struct nl_msg *key_msg;
    int ret = 0;

    idx = if_nametoindex(DEFAULT_NAN_IFACE);

    if (check_key_flag((enum key_flag) key_flag)) {
        ALOGE("%s: invalid key_flag", __FUNCTION__);
        return WIFI_ERROR_INVALID_ARGS;
    }

    msg = nlmsg_alloc();
    key_msg = nlmsg_alloc();
    if (!msg || !key_msg) {
        ALOGE("%s: Memory allocation failed\n", __FUNCTION__);
        return WIFI_ERROR_OUT_OF_MEMORY;
    }

    if ((key_flag & KEY_FLAG_PAIRWISE_MASK) ==
        KEY_FLAG_PAIRWISE_RX_TX_MODIFY) {
        ALOGV("%s: nl80211: SET_KEY (pairwise RX/TX modify)", __FUNCTION__);
        genlmsg_put(msg, 0, 0, info->nl80211_family_id, 0, 0,
                    NL80211_CMD_SET_KEY, 0);
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, idx);
        if(!msg)
           goto fail2;
    } else if (alg == WPA_ALG_NONE && (key_flag & KEY_FLAG_RX_TX)) {
        ALOGE("%s: invalid key_flag to delete key", __FUNCTION__);
        ret = WIFI_ERROR_INVALID_ARGS;
        goto fail2;
    } else if (alg == WPA_ALG_NONE) {
        ALOGV("%s: nl80211: DEL_KEY", __FUNCTION__);
        genlmsg_put(msg, 0, 0, info->nl80211_family_id, 0, 0,
                    NL80211_CMD_DEL_KEY, 0);
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, idx);
        if(!msg)
           goto fail2;
    } else {
        suite = wpa_alg_to_cipher_suite((enum wpa_alg) alg, key_len);
        if (!suite) {
            ret = WIFI_ERROR_INVALID_ARGS;
            goto fail2;
        }
        ALOGV("%s: nl80211: NEW_KEY", __FUNCTION__);
        genlmsg_put(msg, 0, 0, info->nl80211_family_id, 0, 0,
                    NL80211_CMD_NEW_KEY, 0);
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, idx);
        if (!msg)
            goto fail2;
        if (nla_put(key_msg, NL80211_KEY_DATA, key_len, key) ||
            nla_put_u32(key_msg, NL80211_KEY_CIPHER, suite))
            goto fail;
        if (seq && seq_len) {
            if (nla_put(key_msg, NL80211_KEY_SEQ, seq_len, seq))
                goto fail;
            ALOGV("%s: NL80211_KEY_SEQ seq=%p, sed_len=%lu", __FUNCTION__, seq, (unsigned long) seq_len);
        }
    }
    if (addr && !is_broadcast_ether_addr(addr)) {
        ALOGV("%s: addr=" MACSTR, __FUNCTION__, MAC2STR(addr));
        if (nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr) ||
            nla_put(msg, NL80211_ATTR_BSS, ETH_ALEN, addr))
            goto fail;
        if ((key_flag & KEY_FLAG_PAIRWISE_MASK) ==
            KEY_FLAG_PAIRWISE_RX ||
            (key_flag & KEY_FLAG_PAIRWISE_MASK) ==
            KEY_FLAG_PAIRWISE_RX_TX_MODIFY) {
            if (nla_put_u8(key_msg, NL80211_KEY_MODE,
                      key_flag == KEY_FLAG_PAIRWISE_RX ? NL80211_KEY_NO_TX : NL80211_KEY_SET_TX))
                goto fail;
        } else if ((key_flag & KEY_FLAG_GROUP_MASK) ==
                    KEY_FLAG_GROUP_RX) {
            ALOGV("%s:    RSN IBSS RX GTK", __FUNCTION__);
            if (nla_put_u32(key_msg, NL80211_KEY_TYPE,
                            NL80211_KEYTYPE_GROUP))
                goto fail;
        } else if (!(key_flag & KEY_FLAG_PAIRWISE)) {
            ALOGV("%s:  key_flag missing PAIRWISE when setting a pairwise key", __FUNCTION__);
            ret = WIFI_ERROR_INVALID_ARGS;
            goto fail;
        } else {
            ALOGV("%s: pairwise key", __FUNCTION__);
        }
    } else if ((key_flag & KEY_FLAG_PAIRWISE) ||
               !(key_flag & KEY_FLAG_GROUP)) {
        ALOGE("%s: invalid key_flag for a broadcast key", __FUNCTION__);
        ret = WIFI_ERROR_INVALID_ARGS;
        goto fail;
    } else {
        ALOGV("%s: broadcast key", __FUNCTION__);
    }
    if (nla_put_u8(key_msg, NL80211_KEY_IDX, key_idx) ||
        nla_put_nested(msg, NL80211_ATTR_KEY, key_msg))
        goto fail;

    ret = nan_send_nl_msg(info, msg);
fail:
    nlmsg_free(msg);
fail2:
    nlmsg_free(key_msg);
    return ret;
}

int nan_pairing_set_keys_from_cache(wifi_handle handle, u8 *src_addr, u8 *bssid,
                                    int cipher, int akmp, int peer_role)
{

    const u8 *tk;
    size_t tk_len;
    enum wpa_alg alg;
    u32 size = 0;
    NanDebugParams cfg_debug;
    struct ptksa_cache_entry *entry;
    struct nan_pairing_peer_info *peer;
    hal_info *info = getHalInfo(handle);
    struct pasn_data *pasn;
    NanCommand *nanCommand = NULL;

    nanCommand = NanCommand::instance(handle);
    if (nanCommand == NULL) {
        ALOGE("%s: Error NanCommand NULL", __FUNCTION__);
        return WIFI_ERROR_UNKNOWN;
    }

    peer = nan_pairing_get_peer_from_list(info->secure_nan, bssid);
    if (!peer) {
        ALOGE("nl80211: Peer not found in the pairing list");
        return WIFI_ERROR_UNKNOWN;
    }
    pasn = &peer->pasn;
    entry = ptksa_cache_get(info->secure_nan->ptksa, bssid, cipher);
    if (!entry) {
        ALOGE("NAN Pairing: peer " MACSTR "not present in PTKSA cache",
              MAC2STR(bssid));
        return WIFI_ERROR_UNKNOWN;
    }

    if (os_memcmp(entry->own_addr, src_addr, ETH_ALEN) != 0) {
        ALOGE("NAN Pairing: src addr " MACSTR " and PTKSA entry src addr " MACSTR " differ",
              MAC2STR(src_addr), MAC2STR(entry->own_addr));
        return WIFI_ERROR_UNKNOWN;
    }

    tk = entry->ptk.tk;
    tk_len = entry->ptk.tk_len;
    alg = wpa_cipher_to_alg(entry->cipher);

    ALOGD("PASN:" MACSTR "present in PTKSA cache",
          MAC2STR(bssid));

    nan_pairing_set_key(info, alg, bssid, 0, 1, NULL, 0, tk, tk_len,
                        KEY_FLAG_PAIRWISE_RX_TX);

    if (peer_role == SECURE_NAN_PAIRING_INITIATOR) {
        memset(&cfg_debug, 0, sizeof(NanDebugParams));
        cfg_debug.cmd = NAN_TEST_MODE_CMD_PMK;
        nan_pasn_kdk_to_ndp_pmk(entry->ptk.kdk, entry->ptk.kdk_len,
                                entry->addr, entry->own_addr,
                                cfg_debug.debug_cmd_data, &size);
        if (!size) {
            ALOGE("%s: Invalid NDP PMK len", __FUNCTION__);
            return WIFI_ERROR_INVALID_ARGS;
        }
        nan_debug_command_config(0, (wifi_interface_handle)info->secure_nan->cb_iface_ctx,
                                 cfg_debug, size + 4);
        nan_pasn_kdk_to_nan_kek(entry->ptk.kdk, entry->ptk.kdk_len, entry->addr,
                                entry->own_addr, akmp, cipher, entry->ptk.kek,
                                &entry->ptk.kek_len);
    } else {
        nan_pasn_kdk_to_nan_kek(entry->ptk.kdk, entry->ptk.kdk_len, entry->own_addr,
                                entry->addr, akmp, cipher, entry->ptk.kek,
                                &entry->ptk.kek_len);
    }
    nan_set_nira_request(0, (wifi_interface_handle)info->secure_nan->cb_iface_ctx,
                         info->secure_nan->dev_nik->nik_data);
    if (!(peer->dcea_cap_info & DCEA_NPK_CACHING_ENABLED)) {
        // Send Pairing Confirmation as Followup with Peer NIK is not mandatory
        NanPairingConfirmInd evt;
        evt.pairing_instance_id = peer->pairing_instance_id;
        evt.rsp_code = NAN_PAIRING_REQUEST_ACCEPT;
        evt.reason_code = NAN_STATUS_SUCCESS;
        evt.enable_pairing_cache = 0;

        if (peer->is_paired)
            evt.nan_pairing_request_type = NAN_PAIRING_VERIFICATION;
        else
            evt.nan_pairing_request_type = NAN_PAIRING_SETUP;

        if (pasn->akmp == WPA_KEY_MGMT_PASN)
            evt.npk_security_association.akm = PASN;
        else
            evt.npk_security_association.akm = SAE;

        if (info->secure_nan->dev_nik)
            memcpy(evt.npk_security_association.local_nan_identity_key,
                   info->secure_nan->dev_nik->nik_data,
                   NAN_IDENTITY_KEY_LEN);

        evt.npk_security_association.npk.pmk_len = pasn->pmk_len;
        memcpy(evt.npk_security_association.npk.pmk, pasn->pmk,
               pasn->pmk_len);

        nanCommand->handleNanPairingConfirm(&evt);
        peer->is_paired = true;
    }
    return WIFI_SUCCESS;
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

int nan_pasn_kdk_to_ndp_pmk(const u8 *kdk, size_t kdk_len, const u8 *spa,
                            const u8 *bssid, u8 *ndp_pmk, u32 *ndp_pmk_len)
{
    u8 tmp[WPA_NDP_PMK_MAX_LEN];
    u8 *data;
    size_t data_len;
    int ret = -1;
    const char *label = "NDP PMK Derivation";

    *ndp_pmk_len = 0;

    if (!kdk || !kdk_len) {
        ALOGE("PASN: No KDK set for NDP PMK derivation");
        return -1;
    }

    if (!bssid || !spa || !ndp_pmk) {
        ALOGE("PASN: Invalid arguments");
        return -1;
    }

    /*
     * NDP-PMK = KDF-256(KDK, “NDP PMK Derivation”, Initiator NMI || Responder NMI)
     */
    data_len = 2 * ETH_ALEN;
    data = (u8 *)os_zalloc(data_len);
    if (!data) {
        ALOGE("%s: Memory allocation failed", __FUNCTION__);
        return -1;
    }

    os_memcpy(data, spa, ETH_ALEN);
    os_memcpy(data + ETH_ALEN, bssid, ETH_ALEN);

    ALOGD("PASN: NDP PMK derivation: SPA=" MACSTR " BSSID=" MACSTR,
          MAC2STR(spa), MAC2STR(bssid));

    ret = sha256_prf(kdk, kdk_len, label, data, data_len, tmp, WPA_NDP_PMK_MAX_LEN);
    if (ret < 0) {
        ALOGE("%s: PMK derivation failed, err = %d", __FUNCTION__, ret);
        goto err;
    }

    os_memcpy(ndp_pmk, tmp, WPA_NDP_PMK_MAX_LEN);
    *ndp_pmk_len = WPA_NDP_PMK_MAX_LEN;

    forced_memzero(tmp, sizeof(tmp));
    ret = 0;
err:
    bin_clear_free(data, data_len);
    return ret;
}

int nan_pasn_kdk_to_opportunistic_npk(const u8 *kdk, size_t kdk_len,
                                      const u8 *spa, const u8 *bssid,
                                      int akmp, int cipher, u8 *opp_npk,
                                      size_t *opp_npk_len)
{
    u8 tmp[WPA_OPP_NPK_MAX_LEN];
    u8 *data;
    size_t data_len, key_len;
    int ret = -1;
    const char *label = "NAN Opportunistic NPK Derivation";

    *opp_npk_len = 0;

    if (!kdk || !kdk_len) {
        ALOGE("PASN: No KDK set for NAN Opportunistic NPK derivation");
        return -1;
    }

    if (!bssid || !spa || !opp_npk) {
        ALOGE("PASN: Invalid arguments");
        return -1;
    }

    /*
     * PASN-Opportunistic-NPK = KDF-256(KDK, “NAN Opportunistic NPK Derivation”, Initiator NMI || Responder NMI)
     */
    data_len = 2 * ETH_ALEN;
    data = (u8 *)os_zalloc(data_len);
    if (!data) {
        ALOGE("%s: Memory allocation failed", __FUNCTION__);
        return -1;
    }

    os_memcpy(data, spa, ETH_ALEN);
    os_memcpy(data + ETH_ALEN, bssid, ETH_ALEN);

    key_len = wpa_cipher_key_len(cipher);

    if (key_len == 0) {
        ALOGE("PASN: Unsupported cipher (0x%x) used in NAN Opportunistic NPK derivation",
              cipher);
        goto err;
    }

    ALOGD("PASN: NAN Opportunistic NPK derivation: SPA=" MACSTR " BSSID=" MACSTR " akmp=0x%x, cipher=0x%x",
          MAC2STR(spa), MAC2STR(bssid), akmp, cipher);

    if (pasn_use_sha384(akmp, cipher))
        ret = sha384_prf(kdk, kdk_len, label, data, data_len, tmp, key_len);
    else
        ret = sha256_prf(kdk, kdk_len, label, data, data_len, tmp, key_len);

    if (ret < 0) {
        ALOGE("%s: sha prf failed, err = %d", __FUNCTION__, ret);
        goto err;
    }

    os_memcpy(opp_npk, tmp, key_len);
    *opp_npk_len = key_len;

    forced_memzero(tmp, sizeof(tmp));
    ret = 0;
err:
    bin_clear_free(data, data_len);
    return ret;
}

int nan_pasn_kdk_to_nan_kek(const u8 *kdk, size_t kdk_len, const u8 *spa,
                            const u8 *bssid, int akmp, int cipher, u8 *nan_kek,
                            size_t *nan_kek_len)
{
    u8 tmp[WPA_KEK_MAX_LEN];
    u8 *data;
    size_t data_len, key_len;
    int ret = -1;
    const char *label = "NAN Management KEK Derivation";

    *nan_kek_len = 0;

    if (!kdk || !kdk_len) {
        ALOGE("PASN: No KDK set for NAN KEK derivation");
        return -1;
    }

    if (!bssid || !spa || !nan_kek) {
        ALOGE("PASN: Invalid arguments");
        return -1;
    }

    /*
     * PASN-KEK = KDF(KDK, “NAN Management KEK Derivation”, Initiator NMI || Responder NMI)
     */
    data_len = 2 * ETH_ALEN;
    data = (u8 *)os_zalloc(data_len);
    if (!data) {
        ALOGE("%s: Memory allocation failed", __FUNCTION__);
        return -1;
    }

    os_memcpy(data, spa, ETH_ALEN);
    os_memcpy(data + ETH_ALEN, bssid, ETH_ALEN);

    key_len = wpa_cipher_key_len(cipher);

    if (key_len == 0) {
        ALOGE("PASN: Unsupported cipher (0x%x) used in NAN KEK derivation",
              cipher);
        goto err;
    }

    ALOGD("PASN: NAN KEK derivation: SPA=" MACSTR " BSSID=" MACSTR " akmp=0x%x, cipher=0x%x",
          MAC2STR(spa), MAC2STR(bssid), akmp, cipher);

    if (pasn_use_sha384(akmp, cipher))
        ret = sha384_prf(kdk, kdk_len, label, data, data_len, tmp, key_len);
    else
        ret = sha256_prf(kdk, kdk_len, label, data, data_len, tmp, key_len);

    if (ret < 0) {
        ALOGE("%s: sha prf failed, err = %d", __FUNCTION__, ret);
        goto err;
    }

    os_memcpy(nan_kek, tmp, key_len);
    *nan_kek_len = key_len;

    forced_memzero(tmp, sizeof(tmp));
    ret = 0;
err:
    bin_clear_free(data, data_len);
    return ret;
}

int nan_pairing_validate_custom_pmkid(void *ctx, const u8 *bssid,
                                      const u8 *pmkid)
{
    int ret;
    struct nan_pairing_peer_info *entry;
    wifi_handle handle = (wifi_handle)ctx;
    hal_info *info = getHalInfo(handle);
    u8 tag[NAN_IDENTITY_TAG_LEN] = {0};
    u8 data[NIR_STR_LEN + NAN_IDENTITY_NONCE_LEN + ETH_ALEN];

    if (!info && !info->secure_nan) {
        ALOGE(" %s: HAL info or Secure NAN is NULL", __FUNCTION__);
        return -1;
    }

    entry = nan_pairing_get_peer_from_list(info->secure_nan, (u8 *)bssid);
    if (!entry) {
        ALOGE(" %s: No Peer in pairing list, ADDR=" MACSTR,
              __FUNCTION__, MAC2STR(bssid));
        return -1;
    }

    os_memset(data, 0, sizeof(data));
    os_memcpy(data, "NIR", NIR_STR_LEN);
    os_memcpy(&data[NIR_STR_LEN], bssid, ETH_ALEN);
    os_memcpy(&data[NIR_STR_LEN + ETH_ALEN], pmkid, NAN_IDENTITY_NONCE_LEN);

    ret = hmac_sha256(entry->peer_nik, NAN_IDENTITY_KEY_LEN, data,
                      sizeof(data), tag);
    if (ret < 0) {
        ALOGE("NAN PASN: Could not derive NIRA Tag, retval = %d", ret);
        return -1;
    }
    if (os_memcmp(tag, &pmkid[NAN_IDENTITY_NONCE_LEN], NAN_IDENTITY_TAG_LEN) != 0) {
        ALOGE("NAN PASN: NIRA TAG mismatch");
        return -1;
    }
    return 0;
}

const u8 *nan_attr_from_nan_ie(const u8 *nan_ie, enum nan_attr_id attr)
{
  const u8 *nan;
  u8 ie_len = nan_ie[1];

  if (ie_len < NAN_IE_HEADER - 2) {
      ALOGV("%s: NAN IE does not contain attr", __FUNCTION__);
      return NULL;
  }
  nan = nan_ie + NAN_IE_HEADER;

  return get_ie(nan, 2 + ie_len - NAN_IE_HEADER, attr);
}

const u8 *nan_get_attr_from_ies(const u8 *ies, size_t ies_len,
                                 enum nan_attr_id attr)
{
  const u8 *nan_ie;

  nan_ie = get_vendor_ie(ies, ies_len, NAN_IE_VENDOR_TYPE);
  if (!nan_ie) {
      ALOGV("%s: NAN IE NULL", __FUNCTION__);
      return NULL;
  }

  return nan_attr_from_nan_ie(nan_ie, attr);
}

void nan_pairing_add_setup_ies(struct wpa_secure_nan *secure_nan,
                               struct pasn_data *pasn, int peer_role)
{
    u8 *pos;
    nan_dcea *dcea;
    nan_csia *csia;
    nan_npba *npba;
    u8 *extra_ies;

    if (!secure_nan || !pasn) {
        ALOGE("%s: Secure NAN/PASN Null ", __FUNCTION__);
        return;
    }

    pasn->extra_ies_len = NAN_IE_HEADER + sizeof(nan_dcea) +
                          sizeof(nan_csia) + sizeof(nan_csa) +
                          sizeof(nan_npba);

    if (peer_role == SECURE_NAN_PAIRING_INITIATOR)
        pasn->extra_ies_len += sizeof(nan_csa);

    if (pasn->extra_ies)
        os_free((u8 *)pasn->extra_ies);

    extra_ies = (u8 *)os_zalloc(pasn->extra_ies_len);

    if (!extra_ies) {
        ALOGE("%s: Memory allocation failed", __FUNCTION__);
        pasn->extra_ies_len = 0;
        return;
    }

    pos = extra_ies;

    // NAN IE header
    *pos++ = WLAN_EID_VENDOR_SPECIFIC;
    *pos++ = pasn->extra_ies_len - 2;
    WPA_PUT_BE32(pos, NAN_IE_VENDOR_TYPE);
    pos += 4;

    dcea = (nan_dcea *)pos;
    dcea->attr_id = NAN_ATTR_ID_DCEA;
    dcea->len = sizeof(nan_dcea) - offsetof(nan_dcea, cap_info);
    if (secure_nan->enable_pairing_setup)
        dcea->cap_info |= DCEA_PARING_SETUP_ENABLED;
    if (secure_nan->enable_pairing_cache)
        dcea->cap_info |= DCEA_NPK_CACHING_ENABLED;
    pos += sizeof(nan_dcea);

    csia = (nan_csia *)pos;
    csia->attr_id = NAN_ATTR_ID_CSIA;
    csia->len = sizeof(nan_csia) - offsetof(nan_csia, caps);
    csia->len += sizeof(nan_csa);
    csia->caps = 0;
    csia->csa[0].cipher = NCS_PK_PASN_128;
    csia->csa[0].pub_id = secure_nan->pub_sub_id;
    if (peer_role == SECURE_NAN_PAIRING_INITIATOR) {
        csia->csa[1].cipher = NCS_SK_128;
        csia->csa[1].pub_id = secure_nan->pub_sub_id;
        csia->len += sizeof(nan_csa);
        pos += sizeof(nan_csa);
    }
    pos += sizeof(nan_csia) + sizeof(nan_csa);

    npba = (nan_npba *)pos;
    npba->attr_id = NAN_ATTR_ID_NPBA;
    npba->len = sizeof(nan_npba) - offsetof(nan_npba, dialog_token);
    npba->dialog_token = 0;
    npba->type_status = 0;
    npba->reason_code = 0;
    npba->bootstrapping_method = secure_nan->supported_bootstrap;

    ALOGV("NAN Pairing Setup IEs: dcea cap_info = %d "
          "npba bootstrapping method = %d", dcea->cap_info,
           npba->bootstrapping_method);
    pasn->extra_ies = extra_ies;
}

void nan_pairing_add_verification_ies(struct wpa_secure_nan *secure_nan,
                                      struct pasn_data *pasn, int peer_role)
{
    u8 *pos;
    nan_dcea *dcea;
    nan_csia *csia;
    nan_nira *nira;
    u8 *extra_ies;

    if (!secure_nan || !pasn || !secure_nan->dev_nik) {
        ALOGE("NAN: NIK not initialized");
        return;
    }

    pasn->extra_ies_len = NAN_IE_HEADER + sizeof(nan_dcea) +
                          sizeof(nan_csia) + sizeof(nan_csa) +
                          offsetof(nan_nira, nonce_tag) +
                          secure_nan->dev_nik->nira_nonce_len +
                          secure_nan->dev_nik->nira_tag_len;

    if (peer_role == SECURE_NAN_PAIRING_INITIATOR)
        pasn->extra_ies_len += sizeof(nan_csa);

    if (pasn->extra_ies)
        os_free((u8 *)pasn->extra_ies);

    extra_ies = (u8 *) os_zalloc(pasn->extra_ies_len);

    if (!extra_ies) {
        ALOGE("%s: Memory allocation failed", __FUNCTION__);
        pasn->extra_ies_len = 0;
        return;
    }

    pos = extra_ies;

    // NAN IE header
    *pos++ = WLAN_EID_VENDOR_SPECIFIC;
    *pos++ = pasn->extra_ies_len - 2;
    WPA_PUT_BE32(pos, NAN_IE_VENDOR_TYPE);
    pos += 4;

    dcea = (nan_dcea *)pos;
    dcea->attr_id = NAN_ATTR_ID_DCEA;
    dcea->len = sizeof(nan_dcea) - offsetof(nan_dcea, cap_info);
    if (secure_nan->enable_pairing_setup)
        dcea->cap_info |= DCEA_PARING_SETUP_ENABLED;
    if (secure_nan->enable_pairing_cache)
        dcea->cap_info |= DCEA_NPK_CACHING_ENABLED;
    pos += sizeof(nan_dcea);

    csia = (nan_csia *)pos;
    csia->attr_id = NAN_ATTR_ID_CSIA;
    csia->len = sizeof(nan_csia) - offsetof(nan_csia, caps);
    csia->len += sizeof(nan_csa);
    csia->caps = 0;
    csia->csa[0].cipher = NCS_PK_PASN_128;
    csia->csa[0].pub_id = secure_nan->pub_sub_id;
    if (peer_role == SECURE_NAN_PAIRING_INITIATOR) {
        csia->csa[1].cipher = NCS_SK_128;
        csia->csa[1].pub_id = secure_nan->pub_sub_id;
        csia->len += sizeof(nan_csa);
        pos += sizeof(nan_csa);
    }
    pos += sizeof(nan_csia) + sizeof(nan_csa);

    nira = (nan_nira *)pos;
    nira->attr_id = NAN_ATTR_ID_NIRA;
    nira->len = 1 + secure_nan->dev_nik->nira_nonce_len +
                 secure_nan->dev_nik->nira_tag_len;
    nira->cipher_ver = 0;
    os_memcpy(nira->nonce_tag, secure_nan->dev_nik->nira_nonce,
              secure_nan->dev_nik->nira_nonce_len);
    os_memcpy(&nira->nonce_tag[secure_nan->dev_nik->nira_nonce_len],
              secure_nan->dev_nik->nira_tag, secure_nan->dev_nik->nira_tag_len);

    ALOGV("NAN Pairing Verification IEs: dcea cap_info = %d", dcea->cap_info);
    pasn->extra_ies = extra_ies;
}

struct wpabuf *nan_pairing_generate_rsn_ie(int akmp, int cipher, u8 *pmkid)
{
    u8 *pos;
    u16 capab;
    u32 suite;
    size_t rsne_len;
    struct rsn_ie_hdr *hdr;
    struct wpabuf *buf = NULL;

    ALOGD("NAN: Generate RSNE");

    rsne_len = sizeof(*hdr) + RSN_SELECTOR_LEN +
               2 + RSN_SELECTOR_LEN + 2 + RSN_SELECTOR_LEN +
               2 + RSN_SELECTOR_LEN + 2 + (pmkid ? PMKID_LEN : 0);

    buf = wpabuf_alloc(rsne_len);
    if (!buf) {
        ALOGE("%s: Memory allocation failed", __FUNCTION__);
        return NULL;
    }

    if (wpabuf_tailroom(buf) < rsne_len) {
        ALOGE("%s: wpabuf tail room small", __FUNCTION__);
        wpabuf_free(buf);
        return NULL;
    }

    hdr = (struct rsn_ie_hdr *)wpabuf_put(buf, rsne_len);
    hdr->elem_id = WLAN_EID_RSN;
    hdr->len = rsne_len - 2;
    WPA_PUT_LE16(hdr->version, RSN_VERSION);
    pos = (u8 *) (hdr + 1);

    /* Group addressed data is not allowed */
    RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED);
    pos += RSN_SELECTOR_LEN;

    /* Add the pairwise cipher */
    WPA_PUT_LE16(pos, 1);
    pos += 2;
    suite = wpa_cipher_to_suite(WPA_PROTO_RSN, cipher);
    RSN_SELECTOR_PUT(pos, suite);
    pos += RSN_SELECTOR_LEN;

    /* Add the AKM suite */
    WPA_PUT_LE16(pos, 1);
    pos += 2;

    switch (akmp) {
    case WPA_KEY_MGMT_PASN:
        RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_PASN);
        break;
#ifdef CONFIG_SAE
    case WPA_KEY_MGMT_SAE:
        RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_SAE);
        break;
#endif /* CONFIG_SAE */
    default:
        ALOGE("NAN: Invalid AKMP=0x%x", akmp);
        wpabuf_free(buf);
        return NULL;
    }
    pos += RSN_SELECTOR_LEN;

    /* RSN Capabilities: PASN mandates both MFP capable and required */
    capab = WPA_CAPABILITY_MFPC | WPA_CAPABILITY_MFPR;
    WPA_PUT_LE16(pos, capab);
    pos += 2;

    if (pmkid) {
        ALOGD("NAN: Adding PMKID");

        WPA_PUT_LE16(pos, 1);
        pos += 2;
        os_memcpy(pos, pmkid, PMKID_LEN);
        pos += PMKID_LEN;
    } else {
        WPA_PUT_LE16(pos, 0);
        pos += 2;
    }

    /* Group addressed management is not allowed */
    RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED);

    return buf;
}

struct wpabuf *nan_pairing_generate_rsnxe(int akmp)
{
    struct wpabuf *buf = NULL;
    size_t flen;
    u16 capab = 0;

    if (akmp == WPA_KEY_MGMT_SAE)
        capab |= BIT(WLAN_RSNX_CAPAB_SAE_H2E);

    if (!capab) {
        ALOGE("%s: no supported caps", __FUNCTION__);
        return NULL; /* no supported extended RSN capabilities */
    }

    flen = (capab & 0xff00) ? 2 : 1;
    buf = wpabuf_alloc(2 + flen);
    if (!buf) {
        ALOGE("%s: Memory allocation failed", __FUNCTION__);
        return NULL;
    }

    if (wpabuf_tailroom(buf) < 2 + flen) {
        ALOGE("%s: wpabuf tail room small", __FUNCTION__);
        wpabuf_free(buf);
        return NULL;
    }
    capab |= flen - 1; /* bit 0-3 = Field length (n - 1) */

    wpabuf_put_u8(buf, WLAN_EID_RSNX);
    wpabuf_put_u8(buf, flen);
    wpabuf_put_u8(buf, capab & 0x00ff);
    capab >>= 8;
    if (capab)
        wpabuf_put_u8(buf, capab);

    return buf;
}

void nan_pairing_set_password(struct nan_pairing_peer_info *peer, u8 *passphrase,
                              u32 len)
{
    const u8 *pairing_ssid;
    size_t pairing_ssid_len;

    if (!peer || !passphrase) {
        ALOGE("%s: peer/passphrase NULL", __FUNCTION__);
        return;
    }

    if (peer->passphrase)
        os_free(peer->passphrase);

    pairing_ssid = reinterpret_cast<const u8 *> (NAN_PAIRING_SSID);
    pairing_ssid_len = strlen(NAN_PAIRING_SSID);
    peer->passphrase = (char *)os_zalloc(len + 1);
    strlcpy(peer->passphrase, reinterpret_cast<const char *> (passphrase),
            len + 1);
    peer->pasn.pt = sae_derive_pt(NULL, pairing_ssid, pairing_ssid_len,
                                  (const u8 *)passphrase, len,
                                  peer->sae_password_id);
    /* Set passpharse for Pairing Responder to validate PASN auth1 frame*/
    peer->pasn.password = peer->passphrase;
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

    if (eloop_init()) {
        ALOGE("Secure NAN eloop init failed");
        return -1;
    }

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

    eloop_run();

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
    eloop_destroy();

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
