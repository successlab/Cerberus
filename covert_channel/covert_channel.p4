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
// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
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
			IP_PROTOCOLS_TCP: parse_tcp;
			IP_PROTOCOLS_UDP: parse_udp;
			default: accept;
		}
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
        inout header_t hdr,
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
        inout header_t hdr,
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
bit<32> global_time1 = 0;

bit<32> reg_c_timer1_res = 0;

bit<32> reg_c2_key = 0;
bit<32> reg_c5_key = 0;

bit<32> reg_c2_toupdate_value = 0;
bit<32> reg_c5_toupdate_value = 0;

bit<32> reg_c2_res = 0;
bit<32> reg_c5_res = 0;

bit<32> reg_c2_reset_flag = 0;

bit<32> extracted_reg_c2_res_slice0 = 0;

bit<32> extracted_reg_c2_res_slice1 = 0;

bit<32> extracted_reg_c2_res_slice2 = 0;

bit<32> extracted_reg_c2_res_slice3 = 0;

bit<1> comp3_flag = 0;

bit<1> comp4_flag = 0;

bit<8> comp5_flag = 0;

bit<4> upload_tag = 0;
bit<3> slice_index = 0;
//ingress_variable_pos
	bit<1> test;
	
Register<bit<32>, bit<32>>(32w65536) reg_c2_w1;
Register<bit<32>, bit<32>>(32w65536) reg_c2_w2;
Register<bit<1>, bit<32>>(32w65536) reg_c5;
Register<bit<32>, bit<32>>(32w65536) reg_c_timer1;
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
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w1) reg_c2_w1_clear = {
	void apply(inout bit<32> value, out bit<32> read_value){
		read_value = value;
		value = 0;
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
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w2) reg_c2_w2_clear = {
	void apply(inout bit<32> value, out bit<32> read_value){
		read_value = value;
		value = 0;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w2) reg_c2_w2_read = {
	void apply(inout bit<32> value, out bit<32> read_value){
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c_timer1) reg_c_timer1_update = {
	void apply(inout bit<32> value, out bit<32> read_value){
		read_value = global_time1 - value;
		value = global_time1;
	}
};

action reg_c2_w1_plus_action(){
	reg_c2_res = reg_c2_w1_plus.execute(reg_c2_key);
}

action reg_c2_w1_update_action(){
	reg_c2_res = reg_c2_w1_update.execute(reg_c2_key);
}

action reg_c2_w1_clear_action(){
	reg_c2_res = reg_c2_w1_clear.execute(reg_c2_key);
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
		reg_c2_w1_clear_action;
		reg_c2_w1_read_action;
	}
}

action reg_c2_w2_plus_action(){
	reg_c2_res = reg_c2_w2_plus.execute(reg_c2_key);
}

action reg_c2_w2_update_action(){
	reg_c2_res = reg_c2_w2_update.execute(reg_c2_key);
}

action reg_c2_w2_clear_action(){
	reg_c2_res = reg_c2_w2_clear.execute(reg_c2_key);
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
		reg_c2_w2_clear_action;
		reg_c2_w2_read_action;
	}
}
action reg_c_timer1_update_action(){
	reg_c_timer1_res = reg_c_timer1_update.execute(reg_c2_key);
}


table reg_c_timer1_table{
	key = {
		reg_c2_key: exact;
	}
	actions = {
		reg_c_timer1_update_action;
	}
}
action extract_reg_c2_slicing_action(bit<32> mask1, bit<32> mask2){
		reg_c2_reset_flag = reg_c2_res & mask1;
		extracted_reg_c2_res_slice0= reg_c2_res & mask2;
}

table reg_c2_slicing_table{

	key = {
		slice_index: exact;
	}

	actions = {
		extract_reg_c2_slicing_action;
	}
}//ingress_register_pos
	
	
bit<1> tcp_flag = 0;
action check_tcp_setflag(bit<1> flag){
	tcp_flag = flag;
}
table check_tcp_table{
	key = {
		hdr.ipv4.protocol: exact;
	}
	actions = {
		check_tcp_setflag;
	}
}

action reg_c_slices(bit<32> slices){
	reg_c2_toupdate_value = slices;
}

table reg_c_dyn_table{
	key = {
		slice_index: exact;
		ig_intr_md.resubmit_flag: exact;
	}
	actions = {
		reg_c_slices;
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
bit<1> tcp_Mflag = 0;
action tcp_setMflag(){
	tcp_Mflag = 1;
}
table tcp_classification_table{
	key = {
		extracted_reg_c2_res_slice0: exact;
	}
	actions = {
		tcp_setMflag;
	}
}

action upload_CPU(bit<4> tag){
	upload_tag = tag;
}
table upload_table{
	key = {
		tcp_Mflag: exact;
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
		hdr.ipv4.dst_addr: exact;
		hdr.tcp.src_port: exact;
		hdr.tcp.dst_port: exact;
	}
	actions = {
		special_flowkey;
	}
}
action normal_timer(){
		global_time1 = ig_prsr_md.global_tstamp[41:10];  //about 8 seconds
	}
table get_timer{
	actions = {
		normal_timer;
		//sensitive_timer;
		//dull_timer;
	}
	default_action = normal_timer();
}
action slicing2(){
	slice_index = reg_c_timer1_res [31:29] & 0x4;
}
action slicing4(){
	slice_index = reg_c_timer1_res [31:29] & 0x6;
}
action slicing8(){
	slice_index = reg_c_timer1_res [31:29] & 0x7;
}
action no_slicing(){
	slice_index = 0;
}
table enable_slicing{
	actions = {
		slicing2;
		slicing4;
		slicing8;
		no_slicing;
		//sensitive_timer;
		//dull_timer;
	}
	default_action = no_slicing();
}
//ingress_table_pos
	
    apply {
	@stage(0){
	get_timer.apply();
	check_tcp_table.apply();
	//set_timer_mask.apply(); //stage 1  last 2 bit --> 00, 01, 10, 11 --> 6+timer, 4+timer+2, 2+timer+4, timer+6 
	//reg_c2_key= hash0.get(hdr.ipv4.src_addr);
	set_flowkey.apply(); //stage 0
	reg_c_timer1_table.apply(); // stage 1
	enable_slicing.apply();
	reg_c_dyn_table.apply(); //stage 2
	
	reg_c2_w1_table.apply(); 	//stage 2
	reg_c2_w2_table.apply(); 	//stage 2
	reg_c2_slicing_table.apply();	//stage 3
	tcp_classification_table.apply();	//stage 4
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
