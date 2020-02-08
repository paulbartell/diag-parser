#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>
#include <assert.h>

#include "session.h"
#include "bit_func.h"
#include "assignment.h"
#include "address.h"
#include "output.h"

void handle_classmark(struct session_info *s, uint8_t *data, uint8_t type)
{
	struct gsm48_classmark2 *cm2 = (struct gsm48_classmark2 *)data;

	s->ms_cipher_mask |= !cm2->a5_1;

	if (type == 2) {
		s->ms_cipher_mask |= (cm2->a5_2 << 1);
		s->ms_cipher_mask |= (cm2->a5_3 << 2);
	}
}

void handle_mi(struct session_info *s, uint8_t *data, uint8_t len, uint8_t new_tmsi)
{
	uint8_t mi_type;

	if (len > GSM48_MI_SIZE) {
		SET_MSG_INFO(s, "FAILED SANITY CHECKS (MI_LEN)");
		return;
	}

	mi_type = data[0] & GSM_MI_TYPE_MASK;
	switch (mi_type) {
	case GSM_MI_TYPE_NONE:
		break;

	case GSM_MI_TYPE_IMSI:
		break;

	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		break;

	case GSM_MI_TYPE_TMSI:
		break;

	default:
		SET_MSG_INFO(s, "FAILED SANITY CHECKS (MI_TYPE)");
		return;
	}
}

void handle_cmreq(struct session_info *s, uint8_t *data)
{
	struct gsm48_service_request *cm = (struct gsm48_service_request *) data;

	switch (cm->cm_service_type) {
	case GSM48_CMSERV_EMERGENCY:
		/* fall-through */
	case GSM48_CMSERV_MO_CALL_PACKET:
		break;
	case GSM48_CMSERV_SMS:
		break;
	case GSM48_CMSERV_SUP_SERV:
		s->ssa = 1;
		break;
	default:
		s->unknown = 1;
	}

	s->started = 1;
	s->closed = 0;

	s->initial_seq = cm->cipher_key_seq & 7;

	handle_classmark(s, ((uint8_t *) &cm->classmark)+1, 2);
}

void handle_serv_req(struct session_info *s, uint8_t *data, unsigned len)
{
	s->started = 1;
	s->closed = 0;
	s->serv_req = 1;

	s->initial_seq = data[0] & 7;
}

void handle_pag_resp(struct session_info *s, uint8_t *data)
{
	struct gsm48_pag_resp *pr = (struct gsm48_pag_resp *) data;

	s->initial_seq = pr->key_seq;

	s->mt = 1;
	s->started = 1;
	s->closed = 0;

	handle_classmark(s, (uint8_t *) (&pr->classmark2) + 1, 2);

	s->pag_mi = pr->mi[0] & GSM_MI_TYPE_MASK;
}

void handle_loc_upd_acc(struct session_info *s, uint8_t *data, unsigned len)
{
	s->locupd = 1;
	s->mo = 1;
	s->lu_acc = 1;

	if ((len > 11) && (data[5] == 0x17)) {
		s->tmsi_realloc = 1;
	}
}

void handle_id_req(struct session_info *s, uint8_t *data)
{
	switch (data[0] & GSM_MI_TYPE_MASK) {
	case GSM_MI_TYPE_IMSI:
		SET_MSG_INFO(s, "IDENTITY REQUEST, IMSI");
		if (s->cipher) {
			s->iden_imsi_ac = 1;
		} else {
			s->iden_imsi_bc = 1;
		}
		break;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		SET_MSG_INFO(s, "IDENTITY REQUEST, IMEI");
		if (s->cipher) {
			s->iden_imei_ac = 1;
		} else {
			s->iden_imei_bc = 1;
		}
		break;
	}
}

void handle_id_resp(struct session_info *s, uint8_t *data, unsigned len)
{
	SET_MSG_INFO(s, "IDENTITY RESPONSE");

	switch (data[1] & GSM_MI_TYPE_MASK) {
	case GSM_MI_TYPE_IMSI:
		if (s->cipher) {
			s->iden_imsi_ac = 1;
		} else {
			s->iden_imsi_bc = 1;
		}
		break;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		if (s->cipher) {
			s->iden_imei_ac = 1;
		} else {
			s->iden_imei_bc = 1;
		}
		break;
	}
}

void handle_detach(struct session_info *s, uint8_t *data)
{
	struct gsm48_imsi_detach_ind *idi = (struct gsm48_imsi_detach_ind *) data;

	s->started = 1;
	s->closed = 0;

	handle_classmark(s, (uint8_t *) &idi->classmark1, 1);
}

void handle_cc(struct session_info *s, struct gsm48_hdr *dtap, unsigned len, uint8_t ul)
{
	switch (dtap->msg_type & 0x3f) {
	case 0x01:
		SET_MSG_INFO(s, "CALL ALERTING");
		break;
	case 0x02:
		SET_MSG_INFO(s, "CALL PROCEEDING");
		if (s->cipher && !s->fc.enc_rand && !ul)
			s->fc.predict++;
		if (!ul)
			s->mo = 1;
		break;
	case 0x03:
		SET_MSG_INFO(s, "CALL PROGRESS");
		break;
	case 0x05:
		SET_MSG_INFO(s, "CALL SETUP");
		if (!ul)
			s->mt = 1;
		else
			s->mo = 1;

		break;
	case 0x07:
		SET_MSG_INFO(s, "CALL CONNECT");
		break;
	case 0x08:
		SET_MSG_INFO(s, "CALL CONFIRMED");
		if (ul)
			s->mt = 1;
		else
			s->mo = 1;
		break;
	case 0x0f:
		SET_MSG_INFO(s, "CALL CONNECT ACK");
		break;
	case 0x25:
		SET_MSG_INFO(s, "CALL DISCONNECT");
		break;
	case 0x2a:
		SET_MSG_INFO(s, "CALL RELEASE COMPLETE");
		break;
	case 0x2d:
		SET_MSG_INFO(s, "CALL RELEASE");
		break;
	case 0x3a:
		SET_MSG_INFO(s, "CALL FACILITY");
		break;
	case 0x3d:
		SET_MSG_INFO(s, "CALL STATUS");
		break;
	case 0x3e:
		SET_MSG_INFO(s, "CALL NOTIFY");
		break;
	default:
		SET_MSG_INFO(s, "UNKNOWN CC (%02x)", dtap->msg_type & 0x3f);
		s->unknown = 1;
	}
}

void handle_mm(struct session_info *s, struct gsm48_hdr *dtap, unsigned dtap_len, uint32_t fn)
{
	if (dtap_len < sizeof(struct gsm48_hdr)) {
		SET_MSG_INFO(s, "FAILED SANITY CHECKS (MM_LEN)");
		return;
	}

	switch (dtap->msg_type & 0x3f) {
	case 0x01:
		session_reset(s, 1);
		s->started = 1;
		SET_MSG_INFO(s, "IMSI DETACH");
		s->detach = 1;
		s->mo = 1;
		handle_detach(s, dtap->data);
		break;
	case 0x02:
		SET_MSG_INFO(s, "LOC UPD ACCEPT");
		handle_loc_upd_acc(s, dtap->data, dtap_len - 2);
		break;
	case 0x04:
		SET_MSG_INFO(s, "LOC UPD REJECT cause=%d", dtap->data[0]);
		s->locupd = 1;
		s->lu_reject = 1;
		s->lu_rej_cause = dtap->data[0];
		s->mo = 1;
		break;
	case 0x08:
		session_reset(s, 1);
		if (dtap_len < sizeof(struct gsm48_loc_upd_req)) {
			SET_MSG_INFO(s, "FAILED SANITY CHECKS (LUR_DTAP_SIZE)");
			break;
		}
		SET_MSG_INFO(s, "LOC UPD REQUEST");
		break;
	case 0x12:
		if ((dtap_len > 19) && (dtap->data[17] == 0x20) && (dtap->data[18] == 0x10)) {
			SET_MSG_INFO(s, "AUTH REQUEST (UMTS)");
			s->auth = 2;
		} else {
			SET_MSG_INFO(s, "AUTH REQUEST (GSM)");
			s->auth = 1;
		}
		if (!s->auth_req_fn) {
			if (fn) {
				s->auth_req_fn = fn;
			} else {
				s->auth_req_fn = GSM_MAX_FN;
			}
		}
		break;
	case 0x14:
		if ((dtap_len > 6) && (dtap->data[4] == 0x21) && (dtap->data[5] == 0x04)) {
			SET_MSG_INFO(s, "AUTH RESPONSE (UMTS)");
			if (!s->auth) {
				s->auth = 2;
			}
		} else {
			SET_MSG_INFO(s, "AUTH RESPONSE (GSM)");
			if (!s->auth) {
				s->auth = 1;
			}
		}
		if (!s->auth_resp_fn) {
			if (fn) {
				s->auth_resp_fn = fn;
			} else {
				s->auth_resp_fn = GSM_MAX_FN;
			}
		}
		break;
	case 0x18:
		handle_id_req(s, dtap->data);
		break;
	case 0x19:
		handle_id_resp(s, dtap->data, dtap_len - 2);
		break;
	case 0x1a:
		SET_MSG_INFO(s, "TMSI REALLOC COMMAND");
		s->tmsi_realloc = 1;
		break;
	case 0x1b:
		SET_MSG_INFO(s, "TMSI REALLOC COMPLETE");
		s->tmsi_realloc = 1;
		break;
	case 0x21:
		SET_MSG_INFO(s, "CM SERVICE ACCEPT");
		s->mo = 1;
		break;
	case 0x23:
		SET_MSG_INFO(s, "CM SERVICE ABORT");
		s->mo = 1;
		break;
	case 0x24:
		SET_MSG_INFO(s, "CM SERVICE REQUEST");
		session_reset(s, 1);
		s->started = 1;
		s->closed = 0;
		s->serv_req = 1;
		s->mo = 1;
		handle_cmreq(s, dtap->data);
		break;
	case 0x29:
		SET_MSG_INFO(s, "ABORT");
		s->abort = 1;
		break;
	case 0x32:
		SET_MSG_INFO(s, "MM INFORMATION");
		break;
	default:
		SET_MSG_INFO(s, "UNKNOWN MM (%02x)", dtap->msg_type & 0x3f);
		s->unknown = 1;
	}
}

void handle_rr(struct session_info *s, struct gsm48_hdr *dtap, unsigned len, uint32_t fn)
{
	s->rat = RAT_GSM;
	assert(s->new_msg);

	if (!len) {
		return;
	}

	switch (dtap->msg_type) {
	case GSM48_MT_RR_SYSINFO_1:
		SET_MSG_INFO(s, "SYSTEM INFO 1");
		break;
	case GSM48_MT_RR_SYSINFO_2:
		SET_MSG_INFO(s, "SYSTEM INFO 2");
		break;
	case GSM48_MT_RR_SYSINFO_2bis:
		SET_MSG_INFO(s, "SYSTEM INFO 2bis");
		break;
	case GSM48_MT_RR_SYSINFO_2ter:
		SET_MSG_INFO(s, "SYSTEM INFO 2ter");
		break;
	case GSM48_MT_RR_SYSINFO_2quater:
		SET_MSG_INFO(s, "SYSTEM INFO 2quater");
		break;
	case GSM48_MT_RR_SYSINFO_3:
		SET_MSG_INFO(s, "SYSTEM INFO 3");
		break;
	case GSM48_MT_RR_SYSINFO_4:
		SET_MSG_INFO(s, "SYSTEM INFO 4");
		break;
	case GSM48_MT_RR_SYSINFO_5:
		SET_MSG_INFO(s, "SYSTEM INFO 5");
		break;
	case GSM48_MT_RR_SYSINFO_5bis:
		SET_MSG_INFO(s, "SYSTEM INFO 5bis");
		break;
	case GSM48_MT_RR_SYSINFO_5ter:
		SET_MSG_INFO(s, "SYSTEM INFO 5ter");
		break;
	case GSM48_MT_RR_SYSINFO_6:
		SET_MSG_INFO(s, "SYSTEM INFO 6");
		break;
	case GSM48_MT_RR_SYSINFO_13:
		SET_MSG_INFO(s, "SYSTEM INFO 13");
		break;
	case GSM48_MT_RR_CHAN_REL:
		SET_MSG_INFO(s, "CHANNEL RELEASE");
		if (s->cipher && !s->fc.enc_rand)
			s->fc.predict++;

		s->release = 1;
		s->rr_cause = dtap->data[0];
		if ((len > 3) && ((dtap->data[1] & 0xf0) == 0xc0))
			s->have_gprs = 1;

		session_reset(&s[0], 0);
		if (auto_reset) {
			s[1].new_msg = NULL;
		}
		break;
	case GSM48_MT_RR_CLSM_ENQ:
		SET_MSG_INFO(s, "CLASSMARK ENQUIRY");
		break;
	case GSM48_MT_RR_MEAS_REP:
		SET_MSG_INFO(s, "MEASUREMENT REPORT");
		break;
	case GSM48_MT_RR_CLSM_CHG:
		SET_MSG_INFO(s, "CLASSMARK CHANGE");
		handle_classmark(s, &dtap->data[1], 2);
		break;
	case GSM48_MT_RR_PAG_REQ_1:
		SET_MSG_INFO(s, "PAGING REQ 1");
		break;
	case GSM48_MT_RR_PAG_REQ_2:
		SET_MSG_INFO(s, "PAGING REQ 2");
		break;
	case GSM48_MT_RR_PAG_REQ_3:
		SET_MSG_INFO(s, "PAGING REQ 3");
		break;
	case GSM48_MT_RR_IMM_ASS:
		SET_MSG_INFO(s, "IMM ASSIGNMENT");
		break;
	case GSM48_MT_RR_IMM_ASS_EXT:
		SET_MSG_INFO(s, "IMM ASSIGNMENT EXT");
		break;
	case GSM48_MT_RR_IMM_ASS_REJ:
		SET_MSG_INFO(s, "IMM ASSIGNMENT REJECT");
		break;
	case GSM48_MT_RR_PAG_RESP:
		session_reset(s, 1);
		SET_MSG_INFO(s, "PAGING RESPONSE");
		handle_pag_resp(s, dtap->data);
		break;
	case GSM48_MT_RR_HANDO_CMD:
		SET_MSG_INFO(s, "HANDOVER COMMAND");
		parse_assignment(dtap, len, s->cell_arfcns, &s->ga);
		s->handover = 1;
		s->use_jump = 2;
		break;
	case GSM48_MT_RR_HANDO_COMPL:
		SET_MSG_INFO(s, "HANDOVER COMPLETE");
		break;
	case GSM48_MT_RR_ASS_CMD:
		SET_MSG_INFO(s, "ASSIGNMENT COMMAND");
		if ((s->fc.enc-s->fc.enc_null-s->fc.enc_si) == 1)
			s->forced_ho = 1;
		parse_assignment(dtap, len, s->cell_arfcns, &s->ga);
		s->assignment = 1;
		s->use_jump = 1;
		break;
	case GSM48_MT_RR_ASS_COMPL:
		SET_MSG_INFO(s, "ASSIGNMENT COMPLETE");
		s->assign_complete = 1;
		break;
	case GSM48_MT_RR_CIPH_M_COMPL:
		SET_MSG_INFO(s, "CIPHER MODE COMPLETE");
		if (s->cipher_missing < 0) {
			s->cipher_missing = 0;
		} else {
			s->cipher_missing = 1;
		}

		if (!s->cm_comp_first_fn) {
			if (fn) {
				s->cm_comp_first_fn = fn;
			} else {
				s->cm_comp_first_fn = GSM_MAX_FN;
			}
		}

		if (fn) {
			s->cm_comp_last_fn = fn;
		} else {
			s->cm_comp_last_fn = GSM_MAX_FN;
		}

		s->cm_comp_count++;

		if (dtap->data[0] == 0x2b)
			return;

		break;
	case GSM48_MT_RR_GPRS_SUSP_REQ:
		SET_MSG_INFO(s, "GPRS SUSPEND");
		s->have_gprs = 1;
		//tlli
		//rai (lai+rac)
		break;
	case GSM48_MT_RR_CIPH_M_CMD:
		if (!s->cm_cmd_fn) {
			if (fn) {
				s->cm_cmd_fn = fn;
			} else {
				s->cm_cmd_fn = GSM_MAX_FN;
			}
		}

		if (dtap->data[0] & 1) {
			s->cipher = 1 + ((dtap->data[0]>>1) & 7);
			if (!not_zero(s->key, 8))
				s->decoded = 0;
		}
		SET_MSG_INFO(s, "CIPHER MODE COMMAND, A5/%u", s->cipher);
		if (dtap->data[0] & 0x10) {
			s->cmc_imeisv = 1;

			if (s->cipher && !s->fc.enc_rand)
				s->fc.predict++;
		}
		s->cipher_missing = -1;
		break;
	case 0x60:
		SET_MSG_INFO(s, "UTRAN CLASSMARK");
		break;
	default:
		SET_MSG_INFO(s, "UNKNOWN RR (%02x)", dtap->msg_type);
		s->unknown = 1;
	}
}

void handle_ss(struct session_info *s, struct gsm48_hdr *dtap, unsigned len)
{
	assert(s != NULL);
	assert(dtap != NULL);

	if (!len) {
		return;
	}

	s->ssa = 1;

	switch (dtap->msg_type & 0x3f) {
	case 0x2a:
		SET_MSG_INFO(s, "SS RELEASE COMPLETE");
		break;
	case 0x3a:
		SET_MSG_INFO(s, "SS FACILITY");
		break;
	case 0x3b:
		SET_MSG_INFO(s, "SS REGISTER");
		break;
	default:
		SET_MSG_INFO(s, "UNKNOWN SS (%02x)", dtap->msg_type & 0x3f);
		s->unknown = 1;
	}
}

void handle_attach_acc(struct session_info *s, uint8_t *data, unsigned len)
{
	s->attach = 1;
	s->att_acc = 1;

	if (len < 9) {
		return;
	}
}

void handle_ra_upd_acc(struct session_info *s, uint8_t *data, unsigned len)
{
	s->raupd = 1;
	s->lu_acc = 1;
}

void handle_gmm(struct session_info *s, struct gsm48_hdr *dtap, unsigned len)
{
	assert(s != NULL);
	assert(dtap != NULL);

	if (!len) {
		return;
	}

	if (s->domain != DOMAIN_PS) {
		SET_MSG_INFO(s, "FAILED SANITY CHECKS (GMM_IN_CS)");
		return;
	}

	s->new_msg->domain = DOMAIN_PS;

	switch (dtap->msg_type & 0x3f) {
	case 0x01:
		session_reset(s, 1);
		SET_MSG_INFO(s, "ATTACH REQUEST");
		break;
	case 0x02:
		SET_MSG_INFO(s, "ATTACH ACCEPT");
		handle_attach_acc(s, dtap->data, len-2);
		break;
	case 0x03:
		SET_MSG_INFO(s, "ATTACH COMPLETE");
		s->att_acc = 1;
		break;
	case 0x04:
		SET_MSG_INFO(s, "ATTACH REJECT");
		break;
	case 0x05:
		SET_MSG_INFO(s, "DETACH REQUEST");
		s->started = 1;
		break;
	case 0x06:
		SET_MSG_INFO(s, "DETACH ACCEPT");
		break;
	case 0x08:
		session_reset(s, 1);
		SET_MSG_INFO(s, "RA UPDATE REQUEST");
		s->raupd = 1;
		s->mo = 1;
		s->started = 1;
		s->closed = 0;
		s->initial_seq = (dtap->data[0] >> 4) & 7;
		break;
	case 0x09:
		SET_MSG_INFO(s, "RA UPDATE ACCEPT");
		handle_ra_upd_acc(s, dtap->data, len - 2);
		break;
	case 0x0a:
		SET_MSG_INFO(s, "RA UPDATE COMPLETE");
		s->raupd = 1;
		break;
	case 0x0b:
		SET_MSG_INFO(s, "RA UPDATE REJECT");
		break;
	case 0x0c:
		session_reset(s, 1);
		SET_MSG_INFO(s, "SERVICE REQUEST");
		handle_serv_req(s, dtap->data, len - 2);
		break;
	case 0x0d:
		SET_MSG_INFO(s, "SERVICE ACCEPT");
		break;
	case 0x0e:
		SET_MSG_INFO(s, "SERVICE REJECT");
		break;
	case 0x10:
		SET_MSG_INFO(s, "PTMSI REALLOC COMMAND");
		break;
	case 0x11:
		SET_MSG_INFO(s, "PTMSI REALLOC COMPLETE");
		break;
	case 0x12:
		SET_MSG_INFO(s, "AUTH AND CIPHER REQUEST");
		if (!s->cipher) {
			s->cipher = dtap->data[0] & 7;
		}
		s->cmc_imeisv = !!(dtap->data[0] & 0x70);
		if ((len > (2 + 20)) && (dtap->data[20] == 0x28)) {
			s->auth = 2;
		} else {
			s->auth = 1;
		}
		break;
	case 0x13:
		SET_MSG_INFO(s, "AUTH AND CIPHER RESPONSE");
		if (!s->auth) {
			s->auth = 1;
		}
		/* Check if IMEISV is included */
		if ((len > (2 + 15)) && (dtap->data[6] == 0x23)) {
			s->cmc_imeisv = 1;
		}
		break;
	case 0x14:
		s->auth = 1;
		SET_MSG_INFO(s, "AUTH AND CIPHER REJECT");
		break;
	case 0x15:
		handle_id_req(s, dtap->data);
		break;
	case 0x16:
		handle_id_resp(s, dtap->data, len - 2);
		break;
	case 0x20:
		SET_MSG_INFO(s, "GMM STATUS");
		break;
	case 0x21:
		SET_MSG_INFO(s, "GMM INFORMATION");
		break;
	default:
		SET_MSG_INFO(s, "UNKNOWN GMM (%02x)", dtap->msg_type & 0x3f);
	}
}

void handle_pdp_accept(struct session_info *s, uint8_t *data, unsigned len)
{
	uint8_t offset;

	/* Skip LLC NSAPI */
	offset = 1;

	/* Skip QoS and Radio priority */
	offset += 1 + data[offset] + 1;
	if (offset >= len) {
		SET_MSG_INFO(s, "FAILED SANITY CHECKS (QOS_LEN_OVER)");
		return;
	}
	/* Check if there is a PDP address */
	if (data[offset++] != 0x2b) {
		SET_MSG_INFO(s, "FAILED SANITY CHECKS (NO_PDP_ADDR)");
		return;
	}
	/* Check if compatible with IPv4 */
	if ((offset + 7 < len) && (data[offset] == 6)) {
		struct in_addr *in = (struct in_addr *) (&data[offset+3]);
		strncpy(s->pdp_ip, inet_ntoa(*in), sizeof(s->pdp_ip));
		s->pdp_ip[15] = 0;
	}
}

void handle_sm(struct session_info *s, struct gsm48_hdr *dtap, unsigned len)
{
	assert(s != NULL);
	assert(dtap != NULL);

	if (len < 2) {
		return;
	}

	if (s->domain != DOMAIN_PS) {
		SET_MSG_INFO(s, "FAILED SANITY CHECKS (SM_IN_CS)");
		return;
	}

	s->new_msg->domain = DOMAIN_PS;

	switch (dtap->msg_type & 0x3f) {
	case 0x01:
		SET_MSG_INFO(s, "ACTIVATE PDP REQUEST");
		s->pdp_activate = 1;
		break;
	case 0x02:
		SET_MSG_INFO(s, "ACTIVATE PDP ACCEPT");
		handle_pdp_accept(s, dtap->data, len-2);
		break;
	case 0x03:
		SET_MSG_INFO(s, "ACTIVATE PDP REJECT");
		break;
	case 0x04:
		SET_MSG_INFO(s, "REQUEST PDP ACTIVATION");
		s->pdp_activate = 1;
		break;
	case 0x05:
		SET_MSG_INFO(s, "REQUEST PDP ACT REJECT");
		break;
	case 0x06:
		SET_MSG_INFO(s, "DEACTIVATE PDP REQUEST");
		break;
	case 0x07:
		SET_MSG_INFO(s, "DEACTIVATE PDP ACCEPT");
		break;
	case 0x08:
		SET_MSG_INFO(s, "MODIFY PDP REQUEST");
		break;
	case 0x09:
		SET_MSG_INFO(s, "MODIFY PDP ACCEPT (MS)");
		break;
	case 0x0a:
		SET_MSG_INFO(s, "MODIFY PDP REQUEST (MS)");
		break;
	case 0x0b:
		SET_MSG_INFO(s, "MODIFY PDP ACCEPT");
		break;
	case 0x0c:
		SET_MSG_INFO(s, "MODIFY PDP REJECT");
		break;
	case 0x0d:
		SET_MSG_INFO(s, "ACTIVATE 2ND PDP REQUEST");
		break;
	case 0x0e:
		SET_MSG_INFO(s, "ACTIVATE 2ND PDP ACCEPT");
		break;
	case 0x0f:
		SET_MSG_INFO(s, "ACTIVATE 2ND PDP REJECT");
		break;
	case 0x15:
		SET_MSG_INFO(s, "SM STATUS");
		break;
	case 0x1b:
		SET_MSG_INFO(s, "REQUEST 2ND PDP ACTIVATION");
		break;
	case 0x1c:
		SET_MSG_INFO(s, "REQUEST 2ND PDP ACT REJECT");
		break;
	default:
		SET_MSG_INFO(s, "UNKNOWN SM (%02x)", dtap->msg_type & 0x3f);
	}
}

void handle_dtap(struct session_info *s, uint8_t *msg, size_t len, uint32_t fn, uint8_t ul)
{
	struct gsm48_hdr *dtap;

	assert(s != NULL);
	assert(s->new_msg != NULL);
	assert(msg != NULL);

	dtap = (struct gsm48_hdr *) msg;
	s->new_msg->info[0] = 0;

	if (len == 0) {
		SET_MSG_INFO(s, "<ZERO LENGTH>");
		return;
	}

	switch (dtap->proto_discr & GSM48_PDISC_MASK) {
	case GSM48_PDISC_CC:
		handle_cc(s, dtap, len, ul);
		break;
	case GSM48_PDISC_MM:
		handle_mm(s, dtap, len, fn);
		break;
	case GSM48_PDISC_RR:
		handle_rr(s, dtap, len, fn);
		break;
	case GSM48_PDISC_MM_GPRS:
		if (auto_reset) {
			handle_gmm(&s[1], dtap, len);
		} else {
			handle_gmm(s, dtap, len);
		}
		break;
	case GSM411_PDISC_SMS:
		SET_MSG_INFO(s, "SMS");
		break;
	case GSM48_PDISC_SM_GPRS:
		if (auto_reset) {
			handle_sm(&s[1], dtap, len);
		} else {
			handle_sm(s, dtap, len);
		}
		break;
	case GSM48_PDISC_NC_SS:
		handle_ss(s, dtap, len);
		break;
	case GSM48_PDISC_GROUP_CC:
		SET_MSG_INFO(s, "GCC");
		break;
	case GSM48_PDISC_BCAST_CC:
		SET_MSG_INFO(s, "BCC");
		break;
	case GSM48_PDISC_PDSS1:
		SET_MSG_INFO(s, "PDSS1");
		break;
	case GSM48_PDISC_PDSS2:
		SET_MSG_INFO(s, "PDSS2");
		break;
	case GSM48_PDISC_LOC:
		SET_MSG_INFO(s, "LCS");
		break;
	default:
		SET_MSG_INFO(s, "Unknown proto_discr %s: %s", (ul ? "UL" : "DL"),
			 osmo_hexdump_nospc((uint8_t *)dtap, len));
	}
}

void update_timestamps(struct session_info *s)
{
	uint32_t fn;

	assert(s != NULL);

	if (!s->new_msg || !s->started)
		return;

	fn = s->new_msg->bb.fn[0];

	if (!s->first_fn) {
		if (fn) {
			s->first_fn = fn;
		} else {
			s->first_fn = GSM_MAX_FN;
		}
	}

	s->last_fn = fn;
}

void handle_radio_msg(struct session_info *s, struct radio_message *m)
{
	static int num_called  = 0;
	if (msg_verbose > 1) {
		fprintf(stderr, "handle_radio_msg %d\n", num_called++);
	}

	assert(s != NULL);
	assert(m != NULL);

	uint8_t ul = !!(m->bb.arfcn[0] & ARFCN_UPLINK);

	m->info[0] = 0;
	m->flags |= MSG_DECODED;

	//s0 = CS (circuit switched) related transation
	//s1 = PS (packet switched) related transation
	int i;
	for(i = 0; i < 1 + !!auto_reset; i++) {
		assert(s[i].domain == i);
		s[i].new_msg = m;
	}

	switch (m->rat) {
	case RAT_GSM:
		switch (m->flags & 0x0f) {
		case MSG_SACCH: //slow associated control channel
			if (s->rat != RAT_GSM)
				break;

			if (msg_verbose > 1) {
				fprintf(stderr, "-> MSG_SACCH\n");
			}
			break;
		case MSG_SDCCH: //standalone dedicated control channel
			if (s->rat != RAT_GSM)
				break;

			if (msg_verbose > 1) {
				fprintf(stderr, "-> MSG_SDCCH\n");
			}
			break;
		case MSG_FACCH:
			if (msg_verbose > 1) {
				fprintf(stderr, "-> MSG_FACCH\n");
			}
			break;
		case MSG_BCCH:
			if (msg_verbose > 1) {
				fprintf(stderr, "-> MSG_BCCH\n");
			}
			handle_dtap(s, &m->msg[1], m->msg_len-1, m->bb.fn[0], ul);
			break;
		default:
			if (msg_verbose > 1) {
				fprintf(stderr, "Wrong MSG flags %02x\n", m->flags);
			}
			printf("Wrong MSG flags %02x\n", m->flags);
			abort();
		}

		//if s->new_msg is not m, then we have freed it.
		if (msg_verbose && s->new_msg == m && m->flags & MSG_DECODED) {
			printf("GSM %s %s %u : %s\n", m->domain ? "PS" : "CS", ul ? "UL" : "DL",
				m->bb.fn[0], m->info[0] ? m->info : osmo_hexdump_nospc(m->msg, m->msg_len));
		}
		break;

	case RAT_UMTS:
		if (m->flags & MSG_SDCCH) {
			s[0].rat = RAT_UMTS;
			s[1].rat = RAT_UMTS;
		} else if (m->flags & MSG_FACCH) {
			s[0].rat = RAT_UMTS;
			s[1].rat = RAT_UMTS;
		} else if (m->flags & MSG_BCCH) {
		} else {
			assert(0);
		}
		if (msg_verbose && s->new_msg == m && m->flags & MSG_DECODED) {
			printf("RRC %s %s %u : %s\n", m->domain ? "PS" : "CS", ul ? "UL" : "DL",
				m->bb.fn[0], m->info[0] ? m->info : osmo_hexdump_nospc(m->bb.data, m->msg_len));
		}
		break;

	case RAT_LTE:
		if (m->flags & MSG_SDCCH) {
			s[0].rat = RAT_LTE;
			s[1].rat = RAT_LTE;
		}
		if (msg_verbose && s->new_msg == m && m->flags & MSG_DECODED) {
			printf("LTE %s %u : %s\n", ul ? "UL" : "DL",
				m->bb.fn[0], m->info[0] ? m->info : osmo_hexdump_nospc(m->bb.data, m->msg_len));
		}
		break;

	default:
		if (msg_verbose) {
			printf("Unhandled RAT: %d\n", m->rat);
		}
		return;
	}

	if (s->new_msg) {
		/* Keep fn timestamps updated */
		assert(m->domain < 2);
		update_timestamps(&s[m->domain]);

		if (s->new_msg->flags & MSG_DECODED) {
			assert(s->new_msg == m);
			s->new_msg = NULL;
			net_send_msg(m);
			free(m);
		} else {
			free(m);
			s->new_msg = NULL;
		}
	}
}

unsigned encapsulate_lapdm(uint8_t *data, unsigned len, uint8_t ul, uint8_t sacch, uint8_t **output)
{
	if (!len)
		return 0;

	/* Prevent LAPDm length overflow */
	if (len > 63) {
		len = 63;
	}

	/* Select final message length */
	unsigned alloc_len;
	if (sacch) {
		alloc_len = 5 + (len < 18 ? 18 : len);
	} else {
		alloc_len = 3 + (len < 20 ? 20 : len);
	}

	/* Allocate message buffer */
	uint8_t *lapdm = malloc(alloc_len);
	if (lapdm == NULL) {
		*output = NULL;
		return 0;
	} else {
		*output = lapdm;
	}

	/* Fake SACCH L1 header */
	unsigned offset = 0;
	if (sacch) {
		lapdm[0] = 0x00;
		lapdm[1] = 0x00;
		offset = 2;
	}

	/* Fake LAPDm header */
	lapdm[offset+0] = (ul ? 0x01 : 0x03);
	lapdm[offset+1] = 0x03;
	lapdm[offset+2] = len << 2 | 0x01;
	offset += 3;

	/* Append actual payload */
	memcpy(&lapdm[offset], data, len);

	/* Add default padding */
	if (len + offset < alloc_len) {
		memset(&lapdm[len + offset], 0x2b, alloc_len - (len + offset));
	}

	return alloc_len;
}

struct radio_message * new_l2(uint8_t *data, uint8_t len, uint8_t rat, uint8_t domain, uint32_t fn, uint8_t ul, uint8_t flags)
{
	struct radio_message *m;

	assert(data != 0);

	m = (struct radio_message *) malloc(sizeof(struct radio_message));

	if (m == 0)
		return 0;

	memset(m, 0, sizeof(struct radio_message));

	m->rat = rat;
	m->domain = domain;
	switch (flags & 0x0f) {
	case MSG_SDCCH:
	case MSG_SACCH:
		m->chan_nr = 0x41;
		break;
	case MSG_FACCH:
		m->chan_nr = 0x08;
		break;
	case MSG_BCCH:
		m->chan_nr = 0x80;
	}
	m->flags = flags | MSG_DECODED;
	m->msg_len = len;
	m->bb.fn[0] = fn;
	m->bb.arfcn[0] = (ul ? ARFCN_UPLINK : 0);
	memcpy(m->msg, data, len);

	return m;
}

struct radio_message * new_l3(uint8_t *data, uint8_t len, uint8_t rat, uint8_t domain, uint32_t fn, uint8_t ul, uint8_t flags)
{
	assert(data != 0);

	unsigned lapdm_len;
	struct radio_message *m;

	if (len == 0)
		return 0;

	uint8_t *lapdm;
	if (flags & MSG_SACCH) {
		lapdm_len = encapsulate_lapdm(data, len, ul, 1, &lapdm);
	} else {
		lapdm_len = encapsulate_lapdm(data, len, ul, 0, &lapdm);
	}

	if (lapdm_len) {
		m = new_l2(lapdm, lapdm_len, rat, domain, fn, ul, flags);
		free(lapdm);
		return m;
	} else {
		return 0;
	}
}
