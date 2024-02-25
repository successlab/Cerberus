/* -*- P4_16 -*- */

/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) Intel Corporation
 * SPDX-License-Identifier: CC-BY-ND-4.0
 */



#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"
#include "util.p4"


header resubmit_type_c {
    bit<8>  type;
    bit<32> f1;
    bit<16> f2;
    bit<8> f3;
}
@pa_container_size("ingress", "md.c.type", 8)
@pa_container_size("ingress", "md.c.f1", 32)
@pa_container_size("ingress", "md.c.f2", 16)
@pa_container_size("ingress", "md.c.f3", 8)
//@pa_container_size("ingress", "md.c.padding", 8)
const bit<32> SIZE16 = 0x0000ffff;
const bit<32> SIZE17 = 0x0001ffff;
const bit<32> SIZE18 = 0x0003ffff;
const bit<32> SIZE19 = 0x0007ffff;
const bit<32> SIZE20 = 0x000fffff;
const bit<3> DPRSR_DIGEST_TYPE_A = 3;
const bit<8> RESUB_TYPE_C = 1;

header port_metadata {
    bit<8>  type;
    bit<32> f1;
    bit<16> f2;
    bit<8> f3;
}
struct metadata_t { 
    port_metadata   port_md;
    bit<8>          resub_type;
    resubmit_type_c a;
	MirrorId_t ing_mir_ses; 
}
header upload_h {
    //pkt_type_t  pkt_type;
	bit<8> upload_type;
}
struct headers_t {
    ethernet_h ethernet;
    vlan_tag_h vlan_tag;
    ipv4_h ipv4;
    ipv6_h ipv6;
    icmp_h icmp;
    tcp_h tcp;
    udp_h udp;

    // Add more headers here.
}
// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
	
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            0 : parse_port_metadata;
            1 : parse_resubmit;
        }
    }
	state parse_port_metadata {
        md.port_md = port_metadata_unpack<port_metadata>(pkt);
        transition parse_ethernet;
    }

    state parse_resubmit {
        md.resub_type = pkt.lookahead<bit<8>>()[7:0];
        transition parse_resub_c;
    }
    state parse_resub_c {
        pkt.extract(md.a);
		//pkt.advance(32);
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
			ETHERTYPE_IPV4: parse_ipv4;
			default: reject;
		}
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
			1: parse_icmp;
			IP_PROTOCOLS_TCP: parse_tcp;
			IP_PROTOCOLS_UDP: parse_udp;
			default: accept;
		}
    }
	state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }
	state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
	state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in metadata_t ig_md,
	  in ingress_intrinsic_metadata_for_deparser_t	ig_intr_dprsr_md) {
	Resubmit() resubmit;
	Mirror() mirror;
    apply {
		if (ig_intr_dprsr_md.resubmit_type == DPRSR_DIGEST_TYPE_A) {
			resubmit.emit(ig_md.a);
		}
		else if(ig_intr_dprsr_md.mirror_type == 1){
			mirror.emit<upload_h>(ig_md.ing_mir_ses, {ig_md.resub_type});
		}
		pkt.emit(hdr);
    }
}

control SwitchIngress(
        inout headers_t hdr,
        inout metadata_t md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
	
CRCPolynomial<bit<32>>(
	32w0x04C11DB7, // polynomial 
	true,          // reversed 
	false,         // use msb?
	false,         // extended?
	
	32w0xFFFFFFFF, // initial shift register value
	32w0xFFFFFFFF  // result xor
	) poly1;
Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly1) hash0;
Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly1) hash1;
bit<1> global_time1 = 0;
bit<1> global_time2 = 0;
bit<1> global_time3 = 0;

bit<1> reg_c_timer1_res = 0;
bit<1> reg_c_timer2_res = 0;
bit<1> reg_c_timer3_res = 0;

bit<32> reg_c2_time_key = 0;
bit<32> reg_c5_time_key = 0;
bit<32> reg_c2_key = 0;
bit<32> reg_c5_key = 0;

bit<32> reg_c2_toupdate_value = 0;
bit<32> reg_c5_toupdate_value = 0;

bit<32> reg_c2_res = 0;
bit<32> reg_c2_cur_res = 0;
bit<32> reg_c5_res = 0;
bit<32> reg_c5_cur_res = 0;

bit<32> reg_c2_reset_flag = 0;
bit<32> reg_c5_reset_flag = 0;

bit<32> extracted_reg_c2_res_slice0 = 0;

bit<32> extracted_reg_c2_res_slice1 = 0;

bit<32> extracted_reg_c2_res_slice2 = 0;

bit<32> extracted_reg_c5_res_slice0 = 0;

bit<32> extracted_reg_c5_res_slice1 = 0;

bit<32> extracted_reg_c5_res_slice2 = 0;

bit<32> extracted_reg_c5_res_slice3 = 0;

bit<32> extracted_reg_c5_res_slice4 = 0;




bit<1> ssdpq_flag = 0;
bit<1> ssdpr_flag = 0;
bit<1> quicq_flag = 0;
bit<1> quicr_flag = 0;
bit<1> http_flag = 0;
bit<1> syn_flag = 0;
bit<1> slowloris_flag = 0;
bit<1> icmpq_flag = 0;
bit<1> icmpr_flag = 0;
bit<1> is_blocked = 0;
bit<1> orbit = 0;
//ingress_variable_pos
	bit<1> test;
	
Register<bit<32>, bit<32>>(32w65536) reg_c2_w1;
Register<bit<32>, bit<32>>(32w65536) reg_c2_w2;
Register<bit<32>, bit<32>>(32w65536) reg_c5_w1;
Register<bit<32>, bit<32>>(32w65536) reg_c5_w2;
Register<bit<1>, bit<32>>(32w65536) reg_c_timer1;
Register<bit<1>, bit<32>>(32w65536) reg_c_timer2;
Register<bit<1>, bit<32>>(32w65536) reg_c_timer3;
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w1) reg_c2_w1_plus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value + reg_c2_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w1) reg_c2_w1_update = {
	void apply(inout bit<32> value, out bit<32> read_value){
		read_value = value;
		value = reg_c2_toupdate_value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w1) reg_c2_w1_minus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value - reg_c2_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w1) reg_c2_w1_read = {
	void apply(inout bit<32> value, out bit<32> read_value){
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w2) reg_c2_w2_plus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value + reg_c2_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w2) reg_c2_w2_update = {
	void apply(inout bit<32> value, out bit<32> read_value){
		read_value = value;
		value = reg_c2_toupdate_value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w2) reg_c2_w2_minus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value - reg_c2_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w2) reg_c2_w2_read = {
	void apply(inout bit<32> value, out bit<32> read_value){
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c5_w1) reg_c5_w1_plus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value + reg_c5_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c5_w1) reg_c5_w1_minus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value - reg_c5_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c5_w1) reg_c5_w1_setbit = {
	void apply(inout bit<32> value, out bit<32> read_value){
		if(orbit == 1)
			value = value | reg_c5_toupdate_value;
		else
			value = reg_c5_toupdate_value; //equal to update
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c5_w1) reg_c5_w1_read = {
	void apply(inout bit<32> value, out bit<32> read_value){
		if(orbit == 1)
			value = value | reg_c5_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c5_w2) reg_c5_w2_plus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value + reg_c5_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c5_w2) reg_c5_w2_minus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value - reg_c5_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c5_w2) reg_c5_w2_setbit = {
	void apply(inout bit<32> value, out bit<32> read_value){
		if(orbit == 1)
			value = value | reg_c5_toupdate_value;
		else
			value = reg_c5_toupdate_value; //equal to update
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c5_w2) reg_c5_w2_read = {
	void apply(inout bit<32> value, out bit<32> read_value){
		if(orbit == 1)
			value = value | reg_c5_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<1>, bit<32>, bit<1>>(reg_c_timer1) reg_c_timer1_update0 = {
	void apply(inout bit<1> value, out bit<1> read_value){
		read_value = value;
		value = 0;
	}
};
RegisterAction<bit<1>, bit<32>, bit<1>>(reg_c_timer1) reg_c_timer1_update1 = {
	void apply(inout bit<1> value, out bit<1> read_value){
		read_value = value;
		value = 1;
	}
};
RegisterAction<bit<1>, bit<32>, bit<1>>(reg_c_timer2) reg_c_timer2_update0 = {
	void apply(inout bit<1> value, out bit<1> read_value){
		read_value = value;
		value = 0;
	}
};
RegisterAction<bit<1>, bit<32>, bit<1>>(reg_c_timer2) reg_c_timer2_update1 = {
	void apply(inout bit<1> value, out bit<1> read_value){
		read_value = value;
		value = 1;
	}
};

action reg_c2_w1_plus_action(){
	reg_c2_cur_res = reg_c2_w1_plus.execute(reg_c2_key);
}

action reg_c2_w1_update_action(){
	reg_c2_cur_res = reg_c2_w1_update.execute(reg_c2_key);
}

action reg_c2_w1_minus_action(){
	reg_c2_w1_minus.execute(reg_c2_key);
}

action reg_c2_w1_read_action(){
	reg_c2_res = reg_c2_w1_read.execute(reg_c2_key);
}
table reg_c2_w1_table{

	key = {
		global_time1: exact;
		reg_c_timer1_res: exact;
		ig_intr_md.resubmit_flag: exact;
	}

	actions = {
		reg_c2_w1_plus_action;
		reg_c2_w1_update_action;
		reg_c2_w1_minus_action;
		reg_c2_w1_read_action;
	}
}

action reg_c2_w2_plus_action(){
	reg_c2_cur_res = reg_c2_w2_plus.execute(reg_c2_key);
}

action reg_c2_w2_update_action(){
	reg_c2_cur_res = reg_c2_w2_update.execute(reg_c2_key);
}

action reg_c2_w2_minus_action(){
	reg_c2_w2_minus.execute(reg_c2_key);
}

action reg_c2_w2_read_action(){
	reg_c2_res = reg_c2_w2_read.execute(reg_c2_key);
}
table reg_c2_w2_table{

	key = {
		global_time1: exact;
		reg_c_timer1_res: exact;
		ig_intr_md.resubmit_flag: exact;
	}

	actions = {
		reg_c2_w2_plus_action;
		reg_c2_w2_update_action;
		reg_c2_w2_minus_action;
		reg_c2_w2_read_action;
	}
}
action reg_c5_w1_plus_action(){
	reg_c5_cur_res = reg_c5_w1_plus.execute(reg_c5_key);
}

action reg_c5_w1_minus_action(){
	reg_c5_w1_minus.execute(reg_c5_key);
}

action reg_c5_w1_setbit_action(){
	reg_c5_cur_res = reg_c5_w1_setbit.execute(reg_c5_key);
}

action reg_c5_w1_read_action(){
	reg_c5_res = reg_c5_w1_read.execute(reg_c5_key);
}
table reg_c5_w1_table{

	key = {
		global_time2: exact;
		reg_c_timer2_res: exact;
		quicq_flag: exact;
		quicr_flag: exact;
		ssdpq_flag: exact;
		ssdpr_flag: exact;
		ig_intr_md.resubmit_flag: exact;
	}

	actions = {
		reg_c5_w1_plus_action;
		reg_c5_w1_minus_action;
		reg_c5_w1_setbit_action;
		reg_c5_w1_read_action;
	}
}

action reg_c5_w2_plus_action(){
	reg_c5_cur_res = reg_c5_w2_plus.execute(reg_c5_key);
}

action reg_c5_w2_minus_action(){
	reg_c5_w2_minus.execute(reg_c5_key);
}

action reg_c5_w2_setbit_action(){
	reg_c5_cur_res = reg_c5_w2_setbit.execute(reg_c5_key);
}

action reg_c5_w2_read_action(){
	reg_c5_res = reg_c5_w2_read.execute(reg_c5_key);
}
table reg_c5_w2_table{

	key = {
		global_time2: exact;
		reg_c_timer2_res: exact;
		quicq_flag: exact;
		quicr_flag: exact;
		ssdpq_flag: exact;
		ssdpr_flag: exact;
		ig_intr_md.resubmit_flag: exact;
	}

	actions = {
		reg_c5_w2_plus_action;
		reg_c5_w2_minus_action;
		reg_c5_w2_setbit_action;
		reg_c5_w2_read_action;
	}
}
action reg_c_timer1_update0_action(){
	reg_c_timer1_res = reg_c_timer1_update0.execute(reg_c2_time_key);
}

action reg_c_timer1_update1_action(){
	reg_c_timer1_res = reg_c_timer1_update1.execute(reg_c2_time_key);
}

table reg_c_timer1_table{

	key = {
		global_time1: exact;
	}

	actions = {
		reg_c_timer1_update0_action;
		reg_c_timer1_update1_action;
	}
}
action reg_c_timer2_update0_action(){
	reg_c_timer2_res = reg_c_timer2_update0.execute(reg_c5_time_key);
}

action reg_c_timer2_update1_action(){
	reg_c_timer2_res = reg_c_timer2_update1.execute(reg_c5_time_key);
}

table reg_c_timer2_table{

	key = {
		global_time2: exact;
	}

	actions = {
		reg_c_timer2_update0_action;
		reg_c_timer2_update1_action;
	}
}
action extract_reg_c2_slicing_action(bit<32> mask1, bit<32> mask2, bit<32> mask3){
		reg_c2_reset_flag = reg_c2_cur_res & mask1;
		extracted_reg_c2_res_slice0= reg_c2_res & mask2;
		extracted_reg_c2_res_slice1= reg_c2_res & mask3;
}

table reg_c2_slicing_table{

	key = {
		global_time1: exact;
	}

	actions = {
		extract_reg_c2_slicing_action;
	}
}
action extract_reg_c5_slicing_action(bit<32> mask1, bit<32> mask2, bit<32> mask3, bit<32> mask4, bit<32> mask5){
		reg_c5_reset_flag = reg_c5_cur_res & mask1;
		extracted_reg_c5_res_slice0= reg_c5_res & mask2;
		extracted_reg_c5_res_slice1= reg_c5_res & mask3;
		extracted_reg_c5_res_slice2= reg_c5_res & mask4;
		extracted_reg_c5_res_slice3= reg_c5_res & mask5;
}

table reg_c5_slicing_table{

	key = {
		global_time1: exact;
	}

	actions = {
		extract_reg_c5_slicing_action;
	}
}
	
action check_icmpq_setflag(){
	icmpq_flag = 1;
}
action check_icmpr_setflag(){
	icmpr_flag = 1;
}
table check_icmp_table{
	key = {
		hdr.icmp.isValid(): exact;
		hdr.icmp.type_: exact;
	}
	actions = {
		check_icmpr_setflag;
		check_icmpq_setflag;
	}
	size = 1024;
}
action check_syn_setflag(){
	syn_flag = 1;
}
table check_syn_table{
	key = {
		hdr.tcp.isValid(): exact;
		hdr.tcp.flags: exact;
	}
	actions = {
		check_syn_setflag;
	}
	size = 1024;
}
action check_http_setflag(){
	http_flag = 1;
}
table check_http_table{
	key = {
		hdr.tcp.dst_port: exact;
	}
	actions = {
		check_http_setflag;
	}
	size = 1024;
}
action check_quicq_setflag(){
	quicq_flag = 1;
	orbit = 1;
}
action check_ssdpq_setflag(){
	ssdpq_flag = 1;
	orbit = 1;
}
table check_quic_ssdp_q_table{
	key = {
		hdr.ipv4.protocol: exact;
		hdr.udp.dst_port: exact;
	}
	actions = {
		check_quicq_setflag;
		check_ssdpq_setflag;
	}
	size = 1024;
}
action check_quicr_setflag(){
	quicr_flag = 1;
}
action check_ssdpr_setflag(){
	ssdpr_flag = 1;
}
table check_quic_ssdp_r_table{
	key = {
		hdr.ipv4.protocol: exact;
		hdr.udp.src_port: exact;
	}
	actions = {
		check_quicr_setflag;
		check_ssdpr_setflag;
	}
	size = 1024;
}
action check_slowloris_setflag(){
	slowloris_flag = 1;
}
table check_slowloris_table{
	key = {
		hdr.ipv4.src_addr: exact;
		hdr.ipv4.dst_addr: exact;
	}
	actions = {
		check_slowloris_setflag;
	}
	size = 1024;
}
action reg_c2_merge(bit<32> slices){
	reg_c2_toupdate_value = slices;
}
action reg_c2_merge1(bit<32> slices){
	reg_c2_toupdate_value = reg_c2_toupdate_value + slices;
}
action reg_c2_reset(){
	reg_c2_toupdate_value = md.a.f1;
}
table reg_c2_dyn_table{
	key = {
		icmpr_flag: exact;
		icmpq_flag: exact;
		syn_flag: exact;
		ig_intr_md.resubmit_flag: exact;
	}
	actions = {
		reg_c2_merge;
		reg_c2_merge1;
		reg_c2_reset;
	}
}

action reg_c5_merge(bit<32> slices){
	reg_c5_toupdate_value = slices;
	//reg_c5_setvalue = setvalue;
}
action reg_c5_merge1(bit<32> slices){
	reg_c5_toupdate_value = reg_c5_toupdate_value + slices;
	//reg_c5_setvalue = setvalue;
}
action reg_c5_reset(){
	reg_c5_toupdate_value = md.a.f1;
}
table reg_c5_dyn_table{
	key = {
		http_flag: exact;
		quicq_flag: exact;
		quicr_flag: exact;
		ssdpq_flag: exact;
		ssdpr_flag: exact;
		slowloris_flag: exact;
		ig_intr_md.resubmit_flag: exact;
	}
	actions = {
		reg_c5_merge;
		reg_c5_merge1;
		reg_c5_reset;
	}
}

bit<1> icmpr_Mflag = 0;
action icmpr_setMflag(){
	icmpr_Mflag = 1;
}
table icmpr_classification_table{
	key = {
		extracted_reg_c2_res_slice0: exact;
	}
	actions = {
		icmpr_setMflag;
	}
}
bit<1> syn_Mflag = 0;
action syn_setMflag(){
	syn_Mflag = 1;
}
table slowloris1_classification_table{
	key = {
		extracted_reg_c2_res_slice1: exact;
	}
	actions = {
		syn_setMflag;
	}
}

bit<1> http_Mflag = 0;
action http_setMflag(){
	http_Mflag = 1;
}
table http_classification_table{
	key = {
		http_flag: exact;
		extracted_reg_c5_res_slice0: exact;
	}
	actions = {
		http_setMflag;
	}
}
bit<1> quica_Mflag = 0;
action quica_setMflag(){
	quica_Mflag = 1;
}
table quica_classification_table{
	key = {
		quicr_flag: exact;
		extracted_reg_c5_res_slice1: exact;
	}
	actions = {
		quica_setMflag;
	}
}
bit<1> ssdpa_Mflag = 0;
action ssdpa_setMflag(){
	ssdpa_Mflag = 1;
}
table ssdpa_classification_table{
	key = {
		ssdpr_flag: exact;
		extracted_reg_c5_res_slice2: exact;
	}
	actions = {
		ssdpa_setMflag;
	}
}
bit<1> slowloris_Mflag = 0;
action slowloris_setMflag(){
	slowloris_Mflag = 1;
}
table slowloris2_classification_table{
	key = {
		slowloris_flag: exact;
		extracted_reg_c5_res_slice3: exact;
	}
	actions = {
		slowloris_setMflag;
	}
}
action upload_CPU(bit<8> tag){
	hdr.ipv4.diffserv = tag;
	ig_tm_md.ucast_egress_port = 2;
}
action resubmit_CPU(){
	md.resub_type = md.a.f3;
}
table upload_table{
	key = {
		icmpr_Mflag: exact;
		syn_Mflag: exact;
		http_Mflag: exact;
		quica_Mflag: exact;
		ssdpa_Mflag: exact;
		slowloris_Mflag: exact;
		ig_intr_md.resubmit_flag: exact;
	}
	actions = {
		upload_CPU;
		resubmit_CPU;
	}
}

 action resubmit_reset(bit<32> content, bit<8> tag){
	ig_dprsr_md.resubmit_type = DPRSR_DIGEST_TYPE_A;
	md.a.f1 = content;
	md.a.f3 = tag;
}
action mirror_to_CPU(){
	md.ing_mir_ses = 10;
	ig_dprsr_md.mirror_type = 1;;
}
table resubmit_table{
	key = {
		reg_c2_reset_flag: exact;
		reg_c5_reset_flag: exact;
		ig_intr_md.resubmit_flag: exact;
	}
	actions = {
		resubmit_reset;
		mirror_to_CPU;
	}
} 
action special_flowkey(bit<16> key){
	reg_c2_key[15:0]= key;
}
action normal_flowkey(){
	reg_c2_key = reg_c2_time_key;
}
table set_flowkey{
	key = {
		hdr.ipv4.src_addr: exact;
	}
	actions = {
		special_flowkey;
		normal_flowkey;
	}
	default_action = normal_flowkey();
}
action special_flowkey5(bit<16> key){
	reg_c5_key[15:0]= key;
}
action normal_flowkey5(){
	reg_c5_key = reg_c5_time_key;
}
table set_flowkey5{
	key = {
		hdr.ipv4.src_addr: exact;
		hdr.ipv4.dst_addr: exact;
	}
	actions = {
		special_flowkey5;
		normal_flowkey5;
	}
	default_action = normal_flowkey5();
}
action drop_packet(){
	is_blocked = 1;
	ig_dprsr_md.drop_ctl=1;
}
table check_blocklist{
	key = {
		hdr.ipv4.src_addr: exact;
		hdr.ipv4.dst_addr: exact;
	}
	actions = {
		drop_packet;
	}
}
//ingress_table_pos
	
    apply {
		@stage(0){
			//first check blocklist
			check_blocklist.apply();
			//get time windows
			global_time1 = ig_prsr_md.global_tstamp[35:35];  //about 32 seconds
			global_time2 = ig_prsr_md.global_tstamp[33:33];  //about 8 seconds
			//get_timer.apply();
			//check packet types
			check_quic_ssdp_q_table.apply();
			check_quic_ssdp_r_table.apply();
			check_slowloris_table.apply();
			check_icmp_table.apply();
			check_syn_table.apply();
			check_http_table.apply();
			//set update value and flowkey
			reg_c5_toupdate_value[15:0] = hdr.ipv4.total_len;
			reg_c5_dyn_table.apply(); 
			reg_c2_dyn_table.apply(); 
			reg_c2_time_key[15:0]= hash0.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr})[15:0];
			//get_c5_time_key.apply();
			if (hdr.udp.isValid()) {
				reg_c5_time_key[15:0]= hash1.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.udp.src_port, hdr.udp.dst_port, hdr.ipv4.protocol})[15:0];
			}
			else if (hdr.tcp.isValid()) {
				reg_c5_time_key[15:0]= hash1.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.udp.src_port, hdr.udp.dst_port, hdr.ipv4.protocol})[15:0];
			}
			//if flow is not blocked, apply tables
			if(is_blocked == 0){
				@stage(1){
				//elephant flow detection
				//update timer
				set_flowkey.apply(); 
				set_flowkey5.apply(); 
				reg_c_timer1_table.apply(); 
				reg_c_timer2_table.apply(); 
				}
				//update register
				reg_c2_w1_table.apply(); 	
				reg_c2_w2_table.apply(); 	
				reg_c5_w1_table.apply(); 	
				reg_c5_w2_table.apply(); 
				//get result from merged register return value	
				reg_c2_slicing_table.apply();	
				reg_c5_slicing_table.apply();	
				//according to result, set flags
				icmpr_classification_table.apply();	
				slowloris1_classification_table.apply();	
				http_classification_table.apply();	
				ssdpa_classification_table.apply();	
				quica_classification_table.apply();	
				slowloris2_classification_table.apply();	
				ig_tm_md.ucast_egress_port = 1;
				//upload special packet (malicious or overflow) to control plane 
				upload_table.apply();	
				//if overflow, resubmit
				resubmit_table.apply();
			}
			//skip egress pipeline
			@stage(1){
				ig_tm_md.bypass_egress = 1w1;
			}
		}
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
		upload_h upload_md;
		pkt.extract(upload_md);
		eg_md.resub_type = upload_md.upload_type;
		transition parse_ethernet;
	}
	state parse_ethernet{
		pkt.extract(hdr.ethernet);
		transition select(hdr.ethernet.ether_type){
			0x800: parse_ipv4;
			default: reject;
		}
	}
    state parse_ipv4{
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}


control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {



    apply {
		pkt.emit(hdr);
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control SwitchEgress( inout header_t hdr,
        inout metadata_t meta,
        in    egress_intrinsic_metadata_t                 eg_intr_md,
        in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
	apply{
		hdr.ipv4.diffserv = meta.resub_type;
		
	}
}


/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
