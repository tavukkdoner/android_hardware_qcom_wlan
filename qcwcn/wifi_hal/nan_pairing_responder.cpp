/*
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc.All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted (subject to the limitations in the disclaimer
 * below) provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided ?with the distribution.
 *
 * Neither the name of Qualcomm Innovation Center, Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY
 * THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT
 * NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef WPA_PASN_LIB

#include "wifi_hal.h"
#include "nan_i.h"
#include "nancommand.h"
#ifdef __cplusplus
extern "C" {
#endif
#include "ap/pmksa_cache_auth.h"
#ifdef __cplusplus
}
#endif

/*
 * Note: Wi-Fi Aware device can act as PASN initiator with one peer and as
 * PASN responder with other peer, so they maintain separate PMKSA cache
 * for each role. This wrapper functions helps to initialise struct
 * rsn_pmksa_cache which is different for initiator and responder.
 */
struct rsn_pmksa_cache * nan_pairing_responder_pmksa_cache_init(void)
{
   return pmksa_cache_auth_init(NULL, NULL);
}


void nan_pairing_responder_pmksa_cache_deinit(struct rsn_pmksa_cache *pmksa)
{
   return pmksa_cache_auth_deinit(pmksa);
}


int nan_pairing_handle_pasn_auth(wifi_handle handle, const u8 *data, size_t len)
{
    int ret = 0;
    u16 bootstrap;
    struct pasn_data *pasn;
    const u8 *nan_attr_ie;
    bool nira_present = false;
    NanCommand *nanCommand = NULL;
    hal_info *info = getHalInfo(handle);
    u16 auth_alg, auth_transaction, status_code;
    struct nan_pairing_peer_info *entry;
    u8 nira_nonce[NAN_IDENTITY_NONCE_LEN];
    u8 nira_tag[NAN_IDENTITY_TAG_LEN];
    const struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *) data;

    nanCommand = NanCommand::instance(handle);
    if (nanCommand == NULL) {
        ALOGE("%s: Error NanCommand NULL", __FUNCTION__);
        return WIFI_ERROR_UNKNOWN;
    }

    if (!mgmt) {
        ALOGE("%s: PASN mgmt frame NULL", __FUNCTION__);
        return WIFI_ERROR_UNKNOWN;
    }

    if (os_memcmp(mgmt->da, nanCommand->getNmi(), NAN_MAC_ADDR_LEN) != 0) {
        ALOGE("PASN Responder: Not our frame");
        return WIFI_ERROR_UNKNOWN;
    }

    auth_alg = le_to_host16(mgmt->u.auth.auth_alg);
    status_code = le_to_host16(mgmt->u.auth.status_code);

    auth_transaction = le_to_host16(mgmt->u.auth.auth_transaction);

    if(auth_alg != WLAN_AUTH_PASN || auth_transaction == 2) {
       ALOGE("PASN Responder: Not PASN frame/Unexpected auth frame, auth_alg = %d",
              auth_alg);
       return WIFI_ERROR_UNKNOWN;
    }

    if (memcmp(info->secure_nan->own_addr, nanCommand->getNmi(), NAN_MAC_ADDR_LEN) != 0) {
        memcpy(info->secure_nan->own_addr, nanCommand->getNmi(), NAN_MAC_ADDR_LEN);
        // Update NIRA when src mac address changed
        if (info->secure_nan->dev_nik)
            nan_pairing_set_nik_nira(info->secure_nan);
    }

    /* PASN authentication M1 frame processing */
    if (auth_transaction == 1) {

        nan_attr_ie = nan_get_attr_from_ies(mgmt->u.auth.variable,
                         len - offsetof(struct ieee80211_mgmt, u.auth.variable),
                         NAN_ATTR_ID_NIRA);

        if (nan_attr_ie) {
            entry = nan_pairing_get_peer_from_list(info->secure_nan,
                                                   (u8 *)mgmt->sa);
            if (!entry || !entry->is_paired) {
                ALOGI("PASN Responder: NIRA present, but peer entry not found");
                return WIFI_ERROR_UNKNOWN;
            }

            nan_nira *nira = (nan_nira *)nan_attr_ie;
            nira_present = true;
            memcpy(nira_nonce, nira->nonce_tag, NAN_IDENTITY_NONCE_LEN);
            memcpy(nira_tag, &nira->nonce_tag[NAN_IDENTITY_NONCE_LEN],
                   NAN_IDENTITY_TAG_LEN);
            bootstrap = entry->peer_supported_bootstrap;
        }

        entry = nan_pairing_add_peer_to_list(info->secure_nan, (u8 *)mgmt->sa);

        if (data && (len < MAX_FRAME_LEN_80211_MGMT)) {
            entry->frame = (struct pasn_auth_frame *)malloc(sizeof(struct pasn_auth_frame));
            if (entry->frame) {
                memcpy(entry->frame->data, data, len);
                entry->frame->len = len;
            }
        }

        nan_attr_ie = nan_get_attr_from_ies(mgmt->u.auth.variable,
                         len - offsetof(struct ieee80211_mgmt, u.auth.variable),
                         NAN_ATTR_ID_DCEA);
        if (nan_attr_ie) {
           nan_dcea *dcea = (nan_dcea *)nan_attr_ie;
           entry->dcea_cap_info = dcea->cap_info;
        }

        nan_attr_ie = nan_get_attr_from_ies(mgmt->u.auth.variable,
                         len - offsetof(struct ieee80211_mgmt, u.auth.variable),
                         NAN_ATTR_ID_NPBA);
        if (nan_attr_ie) {
           nan_npba *npba = (nan_npba *)nan_attr_ie;
           bootstrap = npba->bootstrapping_method;
        }

        entry->peer_supported_bootstrap = bootstrap;
        entry->pairing_instance_id = info->secure_nan->pairing_id++;
        entry->peer_role = SECURE_NAN_PAIRING_INITIATOR;

        NanPairingRequestInd pairingReqInd;

        /* pub_sub_id and requestor_instance_id populated during bootstrapping */
        pairingReqInd.publish_subscribe_id = entry->pub_sub_id;
        pairingReqInd.requestor_instance_id = entry->requestor_instance_id;
        pairingReqInd.pairing_instance_id = entry->pairing_instance_id;
        memcpy(pairingReqInd.peer_disc_mac_addr, (u8 *)mgmt->sa, NAN_MAC_ADDR_LEN);
        if (nira_present) {
            pairingReqInd.nan_pairing_request_type = NAN_PAIRING_VERIFICATION;
            /* The NIRA from peer for Nan pairing verification */
            memcpy(pairingReqInd.nira.nonce, nira_nonce, NAN_IDENTITY_NONCE_LEN);
            memcpy(pairingReqInd.nira.tag, nira_tag, NAN_IDENTITY_TAG_LEN);
            entry->is_paired = true;
        } else {
            pairingReqInd.nan_pairing_request_type = NAN_PAIRING_SETUP;
        }

        if (entry->dcea_cap_info & DCEA_NPK_CACHING_ENABLED)
            pairingReqInd.enable_pairing_cache = 1;

        nanCommand->handleNanPairingReqInd(&pairingReqInd);

    /* PASN authentication M3 frame processing */
    } else if (auth_transaction == 3) {
        entry = nan_pairing_get_peer_from_list(info->secure_nan, (u8 *)mgmt->sa);
        if (!entry) {
            ALOGE("PASN Responder: M3 from different peer");
            return WIFI_SUCCESS;
        }
        pasn = &entry->pasn;
        ret = handle_auth_pasn_3(pasn, pasn->own_addr,
                                 (u8 *)mgmt->sa, mgmt, len);
        if (ret != 0) {
            ALOGE("PASN Responder: Handle PASN Auth3 failed ");
            return WIFI_ERROR_UNKNOWN;
        }
        ptksa_cache_add(info->secure_nan->ptksa, pasn->own_addr,
                        mgmt->sa, pasn->cipher, 43200,
                        &pasn->ptk, NULL, NULL,
                        pasn->akmp);
    }
    return WIFI_SUCCESS;
}
#endif /* WPA_PASN_LIB */
