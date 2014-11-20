#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <stdio.h>

void proto_register_cattp(void);
void proto_reg_handoff_cattp(void);
const char *gen_flag_str(char header_byte);

static int proto_cattp = -1;
static int hf_cattp_flags = -1;
static int hf_cattp_flags_syn = -1;
static int hf_cattp_flags_ack = -1;
static int hf_cattp_flags_eack = -1;
static int hf_cattp_flags_rst = -1;
static int hf_cattp_flags_nul = -1;
static int hf_cattp_flags_seg = -1;

static int hf_cattp_version = -1;
static int hf_cattp_header_len = -1;
static int hf_cattp_src_port = -1;
static int hf_cattp_dst_port = -1;
static int hf_cattp_data_len = -1;
static int hf_cattp_seq_nb = -1;
static int hf_cattp_ack_nb = -1;
static int hf_cattp_win_size = -1;
static int hf_cattp_checksum = -1;
static int hf_cattp_header_variable_len = -1;
static int hf_cattp_data = -1;

#define HF_FLAG_SYN 0x80
#define HF_FLAG_ACK 0x40
#define HF_FLAG_EACK 0x20
#define HF_FLAG_RST 0x10
#define HF_FLAG_NUL 0x08
#define HF_FLAG_SEG 0x04

#define OFF_HEADER_LEN 0x03
#define OFF_SRC_PORT 0x04
#define OFF_DST_PORT 0x06
#define OFF_DATA_LEN 0x08
#define OFF_SEQ_NB 0x0A
#define OFF_ACK_NB 0x0C
#define OFF_WIN_SIZE 0x0E
#define OFF_CHECKSUM 0x10

static const int *flag_fields[] = {
    &hf_cattp_flags_syn,
    &hf_cattp_flags_ack,
    &hf_cattp_flags_eack,
    &hf_cattp_flags_rst,
    &hf_cattp_flags_nul,
    &hf_cattp_flags_seg,
    NULL
};

static const value_string header_flag_vals[] = {
    { HF_FLAG_SYN, "SYN" },
    { HF_FLAG_ACK, "ACK" },
    { HF_FLAG_EACK, "EACK" },
    { HF_FLAG_RST, "RST" },
    { HF_FLAG_NUL, "NUL" },
    { HF_FLAG_SEG, "SEG" },
    { 0, NULL}
};

static gint ett_cattp = -1;
static gint ett_cattp_header = -1;
static gint ett_cattp_data = -1;

static gboolean dissect_cattp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    proto_tree  *cattp_tree, *cattp_header_tree, *cattp_data_tree, *ti;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CATTP");
    col_clear(pinfo->cinfo, COL_INFO);
    if(tree) {
        guint8 header_len = tvb_get_guint8(tvb, 3);
        guint16 data_len = tvb_get_letohs(tvb, 8);
        int full_len = header_len + data_len;
        
        guint8 header_byte = tvb_get_guint8(tvb, 0);
        const char *flag_str = gen_flag_str((char)header_byte);
        
        ti = proto_tree_add_item(tree, proto_cattp, tvb, 0, full_len, ENC_NA);
        cattp_tree = proto_item_add_subtree(ti, ett_cattp);
        cattp_header_tree = proto_item_add_subtree(cattp_tree, ett_cattp_header);
        cattp_data_tree = proto_item_add_subtree(cattp_tree, ett_cattp_data);
        proto_tree_add_bitmask(cattp_header_tree, tvb, 0, hf_cattp_flags, ett_cattp_header, flag_fields, ENC_LITTLE_ENDIAN);//TODO: use tfs_set_notset successfully to show up nicer
        proto_tree_add_item(cattp_header_tree, hf_cattp_version, tvb, 0x00, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cattp_header_tree, hf_cattp_header_len, tvb, OFF_HEADER_LEN, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cattp_header_tree, hf_cattp_src_port, tvb, OFF_SRC_PORT, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cattp_header_tree, hf_cattp_dst_port, tvb, OFF_DST_PORT, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cattp_header_tree, hf_cattp_data_len, tvb, OFF_DATA_LEN, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cattp_header_tree, hf_cattp_seq_nb, tvb, OFF_SEQ_NB, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cattp_header_tree, hf_cattp_ack_nb, tvb, OFF_ACK_NB, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cattp_header_tree, hf_cattp_win_size, tvb, OFF_WIN_SIZE, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cattp_header_tree, hf_cattp_checksum, tvb, OFF_CHECKSUM, 2, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(cattp_data_tree, hf_cattp_data, tvb, header_len, data_len, ENC_STR_HEX);

        col_add_fstr(pinfo->cinfo, COL_INFO, "%d➞%d [%s] Seq=%d Ack=%d Win=%d Len=%d",
                                                tvb_get_letohs(tvb, OFF_SRC_PORT),
                                                tvb_get_letohs(tvb, OFF_DST_PORT),
                                                flag_str,
                                                tvb_get_letohs(tvb, OFF_SEQ_NB),
                                                tvb_get_letohs(tvb, OFF_ACK_NB),
                                                tvb_get_letohs(tvb, OFF_WIN_SIZE),
                                                tvb_get_letohs(tvb, OFF_DATA_LEN));
    }

    return TRUE;
}

static gboolean dissect_cattp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    if(tvb_length(tvb) < 0x12 ||
        tvb_get_guint8(tvb, 3) < 0x12 ||
        tvb_get_guint8(tvb, 3) + tvb_get_letohs(tvb, 8) != tvb_length(tvb)
        ) {
        return FALSE;
    }

    dissect_cattp(tvb, pinfo, tree, data);
    return TRUE;
}

void proto_register_cattp(void) {
    static hf_register_info hf[] = {
        { &hf_cattp_flags, {
            "Header Flags", "cattp.flags", FT_UINT8, BASE_HEX,
            NULL, 0xFC, NULL, HFILL }},
            { &hf_cattp_flags_syn, {
                "SYN", "cattp.flags.syn", FT_BOOLEAN, 0x08,
                TFS(&tfs_supported_not_supported), HF_FLAG_SYN, NULL, HFILL }},
            { &hf_cattp_flags_ack, {
                "ACK", "cattp.flags.ack", FT_BOOLEAN, 0x08,
                TFS(&tfs_supported_not_supported), HF_FLAG_ACK, NULL, HFILL }},
            { &hf_cattp_flags_eack, {
                "EACK", "cattp.flags.eack", FT_BOOLEAN, 0x08,
                TFS(&tfs_supported_not_supported), HF_FLAG_EACK, NULL, HFILL }},
            { &hf_cattp_flags_rst, {
                "RST", "cattp.flags.rst", FT_BOOLEAN, 0x08,
                TFS(&tfs_supported_not_supported), HF_FLAG_RST, NULL, HFILL }},
            { &hf_cattp_flags_nul, {
                "NUL", "cattp.flags.nul", FT_BOOLEAN, 0x08,
                TFS(&tfs_supported_not_supported), HF_FLAG_NUL, NULL, HFILL }},
            { &hf_cattp_flags_seg, {
                "SEG", "cattp.flags.seg", FT_BOOLEAN, 0x08,
                TFS(&tfs_supported_not_supported), HF_FLAG_SEG, NULL, HFILL }},
        { &hf_cattp_version, {
            "CAT-TP Protocol Version", "cattp.version", FT_UINT8, BASE_DEC,
            NULL, 0x03, NULL, HFILL }},
        { &hf_cattp_header_len, {
            "Header Length", "cattp.header_len", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL }},
        { &hf_cattp_src_port, {
            "Source Port", "cattp.src_port", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_cattp_dst_port, {
            "Destination Port", "cattp.dst_port", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_cattp_data_len, {
            "Data Length", "cattp.data_len", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_cattp_seq_nb, {
            "Sequence Number", "cattp.seq_nb", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_cattp_ack_nb, {
            "Acknowledgement Number", "cattp.ack_nb", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_cattp_win_size, {
            "Window Size", "cattp.win_size", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_cattp_checksum, {
            "Checksum", "cattp.checksum", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_cattp_header_variable_len, {
            "Header Variable Area Length", "cattp.header_variable_len", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_cattp_data, {
            "Data", "cattp.data", FT_BYTES, BASE_NONE,
            NULL, 0, NULL, HFILL }}
    };
    
    static gint *ett[] = {
        &ett_cattp,
        &ett_cattp_header,
        &ett_cattp_data
    };

    proto_cattp = proto_register_protocol("CATTP Protocol", "CATTP", "cattp");
    proto_register_field_array(proto_cattp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_cattp(void) {
   /*
    * We want to register for UDP & TCP, as CATTP can work on either of these.
    * We're using a heuristic dissector due to the ports being specified by the CATTP entities
    */
    heur_dissector_add("tcp", dissect_cattp_heur, proto_cattp);
    heur_dissector_add("udp", dissect_cattp_heur, proto_cattp);
}

const char *gen_flag_str(char header_byte) {
    int num_flags, i;
    int max_str_size = 0;
    const char *cstr;
    char *str;
    int offset = 0;

    num_flags = sizeof(header_flag_vals)/sizeof(header_flag_vals[0]);
    for(i=0; i<num_flags; i++) {
        if(header_flag_vals[i].strptr != NULL) {
            max_str_size += strlen(header_flag_vals[i].strptr);
        }
    }

    printf("Attempting to generate flag str. Num_flags = %d, max_str_size = %d, header_byte = 0x%08x\n", num_flags, max_str_size, header_byte);

    str = cstr = (char *) wmem_alloc(wmem_packet_scope(), max_str_size);
    str[0] = '\0';
    printf("  str[0x%08x] = \"%s\", cstr[0x%08x] = \"%s\"\n", str, str, cstr, cstr);

    for(i=0; i<num_flags; i++) {
        printf("    Checking header byte against 0x%08x", header_flag_vals[i].value);
        if((header_byte & header_flag_vals[i].value) != 0) {
            printf(", passed - appending %s", header_flag_vals[i].strptr);
            if(cstr[0] != '\0') {
                str = g_stpcpy(str, ", ");
            }
            str = g_stpcpy(str, header_flag_vals[i].strptr);
        } else {
            printf(", failed - not appending %s", header_flag_vals[i].strptr);
        }
        printf(", str[0x%08x] = \"%s\", cstr[0x%08x] = \"%s\"\n", str, str, cstr, cstr);
    }

    if(cstr[0] == '\0') {
        cstr = "NONE";
    }


    return cstr;
}
