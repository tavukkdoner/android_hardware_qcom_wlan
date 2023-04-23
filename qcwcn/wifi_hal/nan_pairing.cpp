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
    mentry->pasn.send_mgmt = nan_send_tx_mgmt;
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
