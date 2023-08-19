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
    apply {
		if (ig_intr_dprsr_md.resubmit_type == DPRSR_DIGEST_TYPE_A) {
			resubmit.emit(ig_md.a);
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
	
bit<1> comp0_flag = 0;

bit<2> comp1_flag = 0;

bit<1> comp2_flag = 0;
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

bit<32> reg_c2_key = 0;
bit<32> reg_c5_key = 0;

bit<32> reg_c2_toupdate_value = 0;
bit<32> reg_c5_toupdate_value = 0;

bit<32> reg_c2_res = 0;
bit<32> reg_c5_res = 0;

bit<32> reg_c2_reset_flag = 0;
bit<32> reg_c5_reset_flag = 0;

bit<32> extracted_reg_c2_res_slice0 = 0;

bit<32> extracted_reg_c2_res_slice1 = 0;

bit<32> extracted_reg_c2_res_slice2 = 0;

bit<32> extracted_reg_c2_res_slice3 = 0;

bit<32> extracted_reg_c5_res_slice0 = 0;

bit<32> extracted_reg_c5_res_slice1 = 0;

bit<32> extracted_reg_c5_res_slice2 = 0;

bit<32> extracted_reg_c5_res_slice3 = 0;

bit<32> extracted_reg_c5_res_slice4 = 0;

bit<1> comp3_flag = 0;

bit<1> comp4_flag = 0;

bit<8> comp5_flag = 0;

bit<4> upload_tag = 0;
bit<1> ssdpq_flag = 0;
bit<1> ssdpr_flag = 0;
bit<1> dnsq_flag = 0;
bit<1> dnsr_flag = 0;
bit<1> ntaq_flag = 0;
bit<1> ntar_flag = 0;
bit<1> http_flag = 0;
bit<1> syn_flag = 0;
bit<1> slowloris_flag = 0;
bit<1> icmpq_flag = 0;
bit<1> icmpr_flag = 0;
bit<1> udp_flag = 0;
bit<1> coremelt_flag = 0;
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
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c5_w1) reg_c5_w1_update = {
	void apply(inout bit<32> value, out bit<32> read_value){
		read_value = value;
		value = reg_c5_toupdate_value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c5_w1) reg_c5_w1_setbit = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value | reg_c5_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c5_w1) reg_c5_w1_read = {
	void apply(inout bit<32> value, out bit<32> read_value){
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c5_w2) reg_c5_w2_plus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value + reg_c5_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c5_w2) reg_c5_w2_update = {
	void apply(inout bit<32> value, out bit<32> read_value){
		read_value = value;
		value = reg_c5_toupdate_value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c5_w2) reg_c5_w2_setbit = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value | reg_c5_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c5_w2) reg_c5_w2_read = {
	void apply(inout bit<32> value, out bit<32> read_value){
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
RegisterAction<bit<1>, bit<32>, bit<1>>(reg_c_timer3) reg_c_timer3_update0 = {
	void apply(inout bit<1> value, out bit<1> read_value){
		read_value = value;
		value = 0;
	}
};
RegisterAction<bit<1>, bit<32>, bit<1>>(reg_c_timer3) reg_c_timer3_update1 = {
	void apply(inout bit<1> value, out bit<1> read_value){
		read_value = value;
		value = 1;
	}
};

action reg_c2_w1_plus_action(){
	reg_c2_res = reg_c2_w1_plus.execute(reg_c2_key);
}

action reg_c2_w1_update_action(){
	reg_c2_res = reg_c2_w1_update.execute(reg_c2_key);
}

action reg_c2_w1_minus_action(){
	reg_c2_res = reg_c2_w1_minus.execute(reg_c2_key);
}

action reg_c2_w1_read_action(){
	reg_c2_res = reg_c2_w1_read.execute(reg_c2_key);
}
table reg_c2_w1_table{

	key = {
		global_time1: exact;
		global_time2: exact;
		reg_c_timer1_res: exact;
		reg_c_timer2_res: exact;
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
	reg_c2_res = reg_c2_w2_plus.execute(reg_c2_key);
}

action reg_c2_w2_update_action(){
	reg_c2_res = reg_c2_w2_update.execute(reg_c2_key);
}

action reg_c2_w2_minus_action(){
	reg_c2_res = reg_c2_w2_minus.execute(reg_c2_key);
}

action reg_c2_w2_read_action(){
	reg_c2_res = reg_c2_w2_read.execute(reg_c2_key);
}
table reg_c2_w2_table{

	key = {
		global_time1: exact;
		global_time2: exact;
		reg_c_timer1_res: exact;
		reg_c_timer2_res: exact;
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
	reg_c5_res = reg_c5_w1_plus.execute(reg_c5_key);
}

action reg_c5_w1_update_action(){
	reg_c5_res = reg_c5_w1_update.execute(reg_c5_key);
}

action reg_c5_w1_setbit_action(){
	reg_c5_res = reg_c5_w1_setbit.execute(reg_c5_key);
}

action reg_c5_w1_read_action(){
	reg_c5_res = reg_c5_w1_read.execute(reg_c5_key);
}
table reg_c5_w1_table{

	key = {
		global_time3: exact;
		reg_c_timer3_res: exact;
		dnsq_flag: exact;
		dnsr_flag: exact;
		ssdpq_flag: exact;
		ssdpr_flag: exact;
		ntaq_flag: exact;
		ntar_flag: exact;
		ig_intr_md.resubmit_flag: exact;
	}

	actions = {
		reg_c5_w1_plus_action;
		reg_c5_w1_update_action;
		reg_c5_w1_setbit_action;
		reg_c5_w1_read_action;
	}
}

action reg_c5_w2_plus_action(){
	reg_c5_res = reg_c5_w2_plus.execute(reg_c5_key);
}

action reg_c5_w2_update_action(){
	reg_c5_res = reg_c5_w2_update.execute(reg_c5_key);
}

action reg_c5_w2_setbit_action(){
	reg_c5_res = reg_c5_w2_setbit.execute(reg_c5_key);
}

action reg_c5_w2_read_action(){
	reg_c5_res = reg_c5_w2_read.execute(reg_c5_key);
}
table reg_c5_w2_table{

	key = {
		global_time3: exact;
		reg_c_timer3_res: exact;
		ig_intr_md.resubmit_flag: exact;
	}

	actions = {
		reg_c5_w2_plus_action;
		reg_c5_w2_update_action;
		reg_c5_w2_setbit_action;
		reg_c5_w2_read_action;
	}
}
action reg_c_timer1_update0_action(){
	reg_c_timer1_res = reg_c_timer1_update0.execute(reg_c2_key);
}

action reg_c_timer1_update1_action(){
	reg_c_timer1_res = reg_c_timer1_update1.execute(reg_c2_key);
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
	reg_c_timer2_res = reg_c_timer2_update0.execute(reg_c2_key);
}

action reg_c_timer2_update1_action(){
	reg_c_timer2_res = reg_c_timer2_update1.execute(reg_c2_key);
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
action reg_c_timer3_update0_action(){
	reg_c_timer3_res = reg_c_timer3_update0.execute(reg_c5_key);
}

action reg_c_timer3_update1_action(){
	reg_c_timer3_res = reg_c_timer3_update1.execute(reg_c5_key);
}

table reg_c_timer3_table{

	key = {
		global_time3: exact;
	}

	actions = {
		reg_c_timer3_update0_action;
		reg_c_timer3_update1_action;
	}
}
action extract_reg_c2_slicing_action(bit<32> mask1, bit<32> mask2, bit<32> mask3, bit<32> mask4, bit<32> mask5){
		reg_c2_reset_flag = reg_c2_res & mask1;
		extracted_reg_c2_res_slice0= reg_c2_res & mask2;
		extracted_reg_c2_res_slice1= reg_c2_res & mask3;
		extracted_reg_c2_res_slice2= reg_c2_res & mask4;
		extracted_reg_c2_res_slice3= reg_c2_res & mask5;
}

table reg_c2_slicing_table{

	key = {
		global_time1: exact;
	}

	actions = {
		extract_reg_c2_slicing_action;
	}
}//ingress_register_pos
action extract_reg_c5_slicing_action(bit<32> mask1, bit<32> mask2, bit<32> mask3, bit<32> mask4, bit<32> mask5){
		reg_c5_reset_flag = reg_c5_res & mask1;
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
}//ingress_register_pos	
	
action check_icmpq_setflag(bit<1> flag){
	icmpq_flag = flag;
}
action check_icmpr_setflag(bit<1> flag){
	icmpr_flag = flag;
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
}
action check_udp_setflag(bit<1> flag){
	udp_flag = flag;
}
table check_udp_table{
	key = {
		hdr.udp.isValid(): exact;
	}
	actions = {
		check_udp_setflag;
	}
}
action check_coremelt_setflag(bit<1> flag){
	coremelt_flag = flag;
}
table check_coremelt_table{
	key = {
		hdr.ipv4.isValid(): exact;
	}
	actions = {
		check_coremelt_setflag;
	}
}
action check_dnsq_setflag(bit<1> flag){
	dnsq_flag = flag;
}
table check_dnsq_table{
	key = {
		hdr.ipv4.protocol: exact;
		hdr.udp.dst_port: exact;
	}
	actions = {
		check_dnsq_setflag;
	}
}
action check_dnsr_setflag(bit<1> flag){
	dnsr_flag = flag;
}
table check_dnsr_table{
	key = {
		hdr.ipv4.protocol: exact;
		hdr.udp.src_port: exact;
	}
	actions = {
		check_dnsr_setflag;
	}
}

action check_ssdpq_setflag(bit<1> flag){
	ssdpq_flag = flag;
}
table check_ssdpq_table{
	key = {
		hdr.ipv4.protocol: exact;
		hdr.udp.dst_port: exact;
	}
	actions = {
		check_ssdpq_setflag;
	}
}
action check_ssdpr_setflag(bit<1> flag){
	ssdpr_flag = flag;
}
table check_ssdpr_table{
	key = {
		hdr.ipv4.protocol: exact;
		hdr.udp.src_port: exact;
	}
	actions = {
		check_ssdpr_setflag;
	}
}
action check_ntaq_setflag(bit<1> flag){
	ntaq_flag = flag;
}
table check_ntaq_table{
	key = {
		hdr.ipv4.protocol: exact;
		hdr.udp.dst_port: exact;
	}
	actions = {
		check_ntaq_setflag;
	}
}
action check_ntar_setflag(bit<1> flag){
	ntar_flag = flag;
}
table check_ntar_table{
	key = {
		hdr.ipv4.protocol: exact;
		hdr.udp.src_port: exact;
	}
	actions = {
		check_ntar_setflag;
	}
}
action check_slowloris_setflag(bit<1> flag){
	slowloris_flag = flag;
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
action reg_c2_reset(bit<32> slices){
	reg_c2_toupdate_value = md.a.f1;
}
table reg_c2_dyn_table{
	key = {
		icmpr_flag: exact;
		icmpq_flag: exact;
		udp_flag: exact;
		coremelt_flag: exact;
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
}
action reg_c5_merge1(bit<32> slices){
	reg_c5_toupdate_value = reg_c5_toupdate_value + slices;
}
action reg_c5_reset(bit<32> slices){
	reg_c5_toupdate_value = md.a.f1;
}
table reg_c5_dyn_table{
	key = {
		dnsq_flag: exact;
		ssdpq_flag: exact;
		ntaq_flag: exact;
		ig_intr_md.resubmit_flag: exact;
	}
	actions = {
		reg_c5_merge;
		reg_c5_merge1;
		reg_c5_reset;
	}
}

action comp4_setflag(bit<1> flag){
	comp4_flag = flag;
}
table comp4_table{
	key = {
		ig_intr_md.resubmit_flag: exact;
	}
	actions = {
		comp4_setflag;
	}
}
bit<1> icmpq_Mflag = 0;
action icmpq_setMflag(){
	icmpq_Mflag = 1;
}
table icmpq_classification_table{
	key = {
		extracted_reg_c2_res_slice0: exact;
	}
	actions = {
		icmpq_setMflag;
	}
}
bit<1> icmpr_Mflag = 0;
action icmpr_setMflag(){
	icmpr_Mflag = 1;
}
table icmpr_classification_table{
	key = {
		extracted_reg_c2_res_slice1: exact;
	}
	actions = {
		icmpr_setMflag;
	}
}
bit<1> coremelt_Mflag = 0;
action coremelt_setMflag(){
	coremelt_Mflag = 1;
}
table coremelt_classification_table{
	key = {
		extracted_reg_c2_res_slice2: exact;
	}
	actions = {
		coremelt_setMflag;
	}
}
bit<1> udp_Mflag = 0;
action udp_setMflag(){
	udp_Mflag = 1;
}
table udp_classification_table{
	key = {
		extracted_reg_c2_res_slice3: exact;
	}
	actions = {
		udp_setMflag;
	}
}

bit<1> dnsf_Mflag = 0;
action dnsf_setMflag(){
	dnsf_Mflag = 1;
}
table dnsf_classification_table{
	key = {
		dnsq_flag: exact;
		extracted_reg_c5_res_slice0: exact;
	}
	actions = {
		dnsf_setMflag;
	}
}
bit<1> dnsa_Mflag = 0;
action dnsa_setMflag(){
	dnsa_Mflag = 1;
}
table dnsa_classification_table{
	key = {
		dnsr_flag: exact;
		extracted_reg_c5_res_slice1: exact;
	}
	actions = {
		dnsa_setMflag;
	}
}
bit<1> ntaa_Mflag = 0;
action ntaa_setMflag(){
	ntaa_Mflag = 1;
}
table ntaa_classification_table{
	key = {
		ntar_flag: exact;
		extracted_reg_c5_res_slice2: exact;
	}
	actions = {
		ntaa_setMflag;
	}
}
bit<1> ssdpa_Mflag = 0;
action ssdpa_setMflag(){
	ssdpa_Mflag = 1;
}
table ssdpa_classification_table{
	key = {
		ssdpr_flag: exact;
		extracted_reg_c5_res_slice3: exact;
	}
	actions = {
		ssdpa_setMflag;
	}
}
action upload_CPU(bit<4> tag){
	upload_tag = tag;
}
table upload_table{
	key = {
		icmpq_Mflag: exact;
		icmpr_Mflag: exact;
		coremelt_Mflag: exact;
		udp_Mflag: exact;
		dnsf_Mflag: exact;
		dnsa_Mflag: exact;
		ntaa_Mflag: exact;
		ssdpa_Mflag: exact;
		comp4_flag: exact;
	}
	actions = {
		upload_CPU;
	}
}

 action resubmit_reset(bit<32> content){
	ig_dprsr_md.resubmit_type = DPRSR_DIGEST_TYPE_A;
	md.a.f1 = content;
}
table resubmit_table{
	key = {
		reg_c2_reset_flag: exact;
		reg_c5_reset_flag: exact;
	}
	actions = {
		resubmit_reset;
	}
} 
action special_flowkey(bit<16> key){
	reg_c2_key[15:0]= key;
}
table set_flowkey{
	key = {
		hdr.ipv4.src_addr: exact;
	}
	actions = {
		special_flowkey;
	}
}
action special_flowkey5(bit<16> key){
	reg_c5_key[15:0]= key;
}
table set_flowkey5{
	key = {
		hdr.ipv4.src_addr: exact;
		hdr.ipv4.dst_addr: exact;
	}
	actions = {
		special_flowkey5;
	}
}
action normal_timer(){
		global_time1 = ig_prsr_md.global_tstamp[33:33];  //about 8 seconds
		global_time2 = ig_prsr_md.global_tstamp[31:31];  //about 8 seconds
		global_time3 = ig_prsr_md.global_tstamp[36:36];  //about 64 seconds
	}
	//action sensitive_timer(){
	//	global_time = ig_prsr_md.global_tstamp[30:30];  //about 1 seconds
	//}
	//action dull_timer(){
	//	global_time = ig_prsr_md.global_tstamp[36:36];  //about 64 seconds
	//}
	table get_timer{
		actions = {
			normal_timer;
			//sensitive_timer;
			//dull_timer;
		}
		default_action = normal_timer();
	}
//ingress_table_pos
	
    apply {
	@stage(0){
	get_timer.apply();
	check_icmp_table.apply();
	check_coremelt_table.apply();
	check_udp_table.apply();
	check_dnsq_table.apply();
	check_dnsr_table.apply();
	check_ssdpq_table.apply();
	check_ssdpr_table.apply();
	check_ntaq_table.apply();
	check_ntar_table.apply();
	reg_c2_toupdate_value[15:0] = hdr.ipv4.total_len;
	reg_c2_dyn_table.apply(); //stage 1
	reg_c5_dyn_table.apply(); //stage 1
	//set_timer_mask.apply(); //stage 1  last 2 bit --> 00, 01, 10, 11 --> 6+timer, 4+timer+2, 2+timer+4, timer+6 
	reg_c2_key[15:0]= hash0.get(hdr.ipv4.src_addr)[15:0];
	reg_c5_key[15:0]= hash1.get(hdr.ipv4.dst_addr)[15:0];
	set_flowkey.apply(); //stage 0
	set_flowkey5.apply(); //stage 1
	reg_c_timer1_table.apply(); // stage 1
	//reg_c_timer2_table.apply(); // stage 1
	reg_c_timer3_table.apply(); // stage 2
	reg_c2_w1_table.apply(); 	//stage 2
	reg_c2_w2_table.apply(); 	//stage 2
	reg_c5_w1_table.apply(); 	//stage 3
	reg_c5_w2_table.apply(); 	//stage 3
	reg_c2_slicing_table.apply();	//stage 3
	reg_c5_slicing_table.apply();	//stage 4
	icmpr_classification_table.apply();	//stage 4
	icmpq_classification_table.apply();	//stage 4
	coremelt_classification_table.apply();	//stage 4
	udp_classification_table.apply();	//stage 4
	dnsf_classification_table.apply();	//stage 4
	dnsa_classification_table.apply();	//stage 5
	ssdpa_classification_table.apply();	//stage 5
	ntaa_classification_table.apply();	//stage 5
	upload_table.apply();	//stage 5
	resubmit_table.apply();//ingress_apply_pos
	}
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;
