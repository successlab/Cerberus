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
header upload_h {
    //pkt_type_t  pkt_type;
	bit<8> upload_type;
}
struct metadata_t { 
    port_metadata   port_md;
    bit<8>          resub_type;
    resubmit_type_c a;
	MirrorId_t ing_mir_ses; 
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
			default: accept;
		}
    }
	state parse_tcp {
        pkt.extract(hdr.tcp);
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
        inout header_t hdr,
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
bit<32> global_time1 = 0;

bit<32> reg_c_timer1_res = 0;

bit<32> reg_time_key = 0;
bit<32> reg_key = 0;

bit<32> reg_toupdate_value = 0;

bit<32> reg_class0_w1_res = 0;
bit<32> reg_class1_w1_res = 0;
bit<32> reg_class2_w1_res = 0;
bit<32> reg_class3_w1_res = 0;
bit<32> reg_class0_w2_res = 0;
bit<32> reg_class1_w2_res = 0;
bit<32> reg_class2_w2_res = 0;
bit<32> reg_class3_w2_res = 0;
bit<32> reg_res = 0;

bit<32> reg_reset_flag01 = 0;
bit<32> reg_reset_flag11 = 0;
bit<32> reg_reset_flag21 = 0;
bit<32> reg_reset_flag31 = 0;
bit<32> reg_reset_flag02 = 0;
bit<32> reg_reset_flag12 = 0;
bit<32> reg_reset_flag22 = 0;
bit<32> reg_reset_flag32 = 0;

bit<32> extracted_reg_class0_res_slice0 = 0;
bit<32> extracted_reg_class1_res_slice0 = 0;
bit<32> extracted_reg_class2_res_slice0 = 0;
bit<32> extracted_reg_class3_res_slice0 = 0;

bit<5> class_index = 0;
bit<2> final_index = 0;
bit<1> is_split = 0;
bit<2> split_key = 0;

bit<4> upload_tag = 0;
bit<3> slice_index = 0;
//ingress_variable_pos
	bit<1> test;
	
Register<bit<32>, bit<32>>(32w65536) reg_class0_w1;
Register<bit<32>, bit<32>>(32w65536) reg_class0_w2;
Register<bit<32>, bit<32>>(32w65536) reg_class1_w1;
Register<bit<32>, bit<32>>(32w65536) reg_class1_w2;
Register<bit<32>, bit<32>>(32w65536) reg_class2_w1;
Register<bit<32>, bit<32>>(32w65536) reg_class2_w2;
Register<bit<32>, bit<32>>(32w65536) reg_class3_w1;
Register<bit<32>, bit<32>>(32w65536) reg_class3_w2;
Register<bit<1>, bit<32>>(32w65536) reg_c5;
Register<bit<32>, bit<32>>(32w131072) reg_c_timer1;
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_class0_w1) reg_class0_w1_plus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value + reg_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_class0_w1) reg_class0_w1_minus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value - reg_toupdate_value;
		read_value = value;
	}
};

RegisterAction<bit<32>, bit<32>, bit<32>>(reg_class1_w1) reg_class1_w1_plus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value + reg_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_class1_w1) reg_class1_w1_minus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value - reg_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_class2_w1) reg_class2_w1_plus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value + reg_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_class2_w1) reg_class2_w1_minus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value - reg_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_class3_w1) reg_class3_w1_plus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value + reg_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_class3_w1) reg_class3_w1_minus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value - reg_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_class0_w2) reg_class0_w2_plus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value + reg_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_class0_w2) reg_class0_w2_minus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value - reg_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_class1_w2) reg_class1_w2_plus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value + reg_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_class1_w2) reg_class1_w2_minus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value - reg_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_class2_w2) reg_class2_w2_plus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value + reg_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_class2_w2) reg_class2_w2_minus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value - reg_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_class3_w2) reg_class3_w2_plus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value + reg_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_class3_w2) reg_class3_w2_minus = {
	void apply(inout bit<32> value, out bit<32> read_value){
		value = value - reg_toupdate_value;
		read_value = value;
	}
};
RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c_timer1) reg_c_timer1_update = {
	void apply(inout bit<32> value, out bit<32> read_value){
		read_value = global_time1 - value;
		value = global_time1;
	}
};

action reg_class0_w1_plus_action(){
	reg_class0_w1_res = reg_class0_w1_plus.execute(reg_key);
}
action reg_class0_w1_minus_action(){
	reg_class0_w1_res = reg_class0_w1_minus.execute(reg_key);
}
table reg_class0_w1_table{

	key = {
		final_index: exact;
		ig_intr_md.resubmit_flag: exact;
		md.a.f3: exact;
	}

	actions = {
		reg_class0_w1_plus_action;
		reg_class0_w1_minus_action;
	}
}

action reg_class1_w1_plus_action(){
	reg_class1_w1_res = reg_class1_w1_plus.execute(reg_key);
}
action reg_class1_w1_minus_action(){
	reg_class1_w1_res = reg_class1_w1_minus.execute(reg_key);
}
table reg_class1_w1_table{

	key = {
		final_index: exact;
		ig_intr_md.resubmit_flag: exact;
		md.a.f3: exact;
	}

	actions = {
		reg_class1_w1_plus_action;
		reg_class1_w1_minus_action;
	}
}

action reg_class2_w1_plus_action(){
	reg_class2_w1_res = reg_class2_w1_plus.execute(reg_key);
}
action reg_class2_w1_minus_action(){
	reg_class2_w1_res = reg_class2_w1_minus.execute(reg_key);
}
table reg_class2_w1_table{

	key = {
		final_index: exact;
		ig_intr_md.resubmit_flag: exact;
		md.a.f3: exact;
	}

	actions = {
		reg_class2_w1_plus_action;
		reg_class2_w1_minus_action;
	}
}

action reg_class3_w1_plus_action(){
	reg_class3_w1_res = reg_class3_w1_plus.execute(reg_key);
}
action reg_class3_w1_minus_action(){
	reg_class3_w1_res = reg_class3_w1_minus.execute(reg_key);
}
table reg_class3_w1_table{

	key = {
		final_index: exact;
		ig_intr_md.resubmit_flag: exact;
		md.a.f3: exact;
	}

	actions = {
		reg_class3_w1_plus_action;
		reg_class3_w1_minus_action;
	}
}

action reg_class0_w2_plus_action(){
	reg_class0_w2_res = reg_class0_w2_plus.execute(reg_key);
}
action reg_class0_w2_minus_action(){
	reg_class0_w2_res = reg_class0_w2_minus.execute(reg_key);
}
table reg_class0_w2_table{

	key = {
		final_index: exact;
		ig_intr_md.resubmit_flag: exact;
		md.a.f3: exact;
	}

	actions = {
		reg_class0_w2_plus_action;
		reg_class0_w2_minus_action;
	}
}

action reg_class1_w2_plus_action(){
	reg_class1_w2_res = reg_class1_w2_plus.execute(reg_key);
}
action reg_class1_w2_minus_action(){
	reg_class1_w2_res = reg_class1_w2_minus.execute(reg_key);
}
table reg_class1_w2_table{

	key = {
		final_index: exact;
		ig_intr_md.resubmit_flag: exact;
		md.a.f3: exact;
	}

	actions = {
		reg_class1_w2_plus_action;
		reg_class1_w2_minus_action;
	}
}

action reg_class2_w2_plus_action(){
	reg_class2_w2_res = reg_class2_w2_plus.execute(reg_key);
}
action reg_class2_w2_minus_action(){
	reg_class2_w2_res = reg_class2_w2_minus.execute(reg_key);
}
table reg_class2_w2_table{

	key = {
		final_index: exact;
		ig_intr_md.resubmit_flag: exact;
		md.a.f3: exact;
	}

	actions = {
		reg_class2_w2_plus_action;
		reg_class2_w2_minus_action;
	}
}

action reg_class3_w2_plus_action(){
	reg_class3_w2_res = reg_class3_w2_plus.execute(reg_key);
}
action reg_class3_w2_minus_action(){
	reg_class3_w2_res = reg_class3_w2_minus.execute(reg_key);
}
table reg_class3_w2_table{

	key = {
		final_index: exact;
		ig_intr_md.resubmit_flag: exact;
		md.a.f3: exact;
	}

	actions = {
		reg_class3_w2_plus_action;
		reg_class3_w2_minus_action;
	}
}

action reg_c_timer1_update_action(){
	//get IPD
	reg_c_timer1_res = reg_c_timer1_update.execute(reg_time_key);
}
table reg_c_timer1_table{
	actions = {
		reg_c_timer1_update_action;
	}
	default_action = reg_c_timer1_update_action();
}

	
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

action resubmit_CPU(){
	md.resub_type = md.a.f3;
}
table upload_table{
	key = {
		ig_intr_md.resubmit_flag: exact;
	}
	actions = {
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
		reg_reset_flag01: exact;
		reg_reset_flag11: exact;
		reg_reset_flag21: exact;
		reg_reset_flag31: exact;
		reg_reset_flag02: exact;
		reg_reset_flag12: exact;
		reg_reset_flag22: exact;
		reg_reset_flag32: exact;
		ig_intr_md.resubmit_flag: exact;
	}
	actions = {
		resubmit_reset;
		mirror_to_CPU;
	}
} 
action special_flowkey(bit<17> key){
	reg_key[16:0]= key;
}
action normal_flowkey(){
	reg_key = reg_time_key;
}
action split_flowkey(){
	reg_key[15:0] = reg_time_key[15:0];
	split_key[0:0] = reg_time_key[16:16];
}
table set_flowkey{
	key = {
		hdr.ipv4.src_addr: exact;
		hdr.ipv4.dst_addr: exact;
		hdr.tcp.src_port: exact;
		hdr.tcp.dst_port: exact;
		is_split: exact;
	}
	actions = {
		special_flowkey;
		normal_flowkey;
		split_flowkey;
	}
	default_action = split_flowkey();
}
action normal_timer(bit<1> split_flag){
		global_time1 = ig_prsr_md.global_tstamp[41:10];  
		is_split = split_flag;
	}
table get_timer{
	actions = {
		normal_timer;
	}
	default_action = normal_timer(1);
}

action extract_reg_slicing_action(bit<32> mask1){
		reg_reset_flag01 = reg_class0_w1_res & mask1;
		reg_reset_flag11 = reg_class1_w1_res & mask1;
		reg_reset_flag21 = reg_class2_w1_res & mask1;
		reg_reset_flag31 = reg_class3_w1_res & mask1;
		reg_reset_flag02 = reg_class0_w2_res & mask1;
		reg_reset_flag12 = reg_class1_w2_res & mask1;
		reg_reset_flag22 = reg_class2_w2_res & mask1;
		reg_reset_flag32 = reg_class3_w2_res & mask1;
}
table reg_slicing_table{

	key = {
		class_index: exact;
		ig_intr_md.resubmit_flag: exact;  //must be 0
	}

	actions = {
		extract_reg_slicing_action;
	}
}

action slicing2(bit<1> segment, bit<32> slice){
	//32-bit --> 16-bitx2
	reg_key[15:15] = class_index[0:0];
	final_index = class_index[3:2];
	reg_toupdate_value = slice;	// class_index[1:1]  1 | 2^16
}
action slicing4(bit<1> segment, bit<32> slice){
	//32-bit --> 8-bitx4
	final_index = class_index[3:2];
	reg_toupdate_value = slice;	// class_index[1:0]  1 | 2^8 | 2^16 | 2^24
}
action slicing8(bit<1> segment, bit<32> slice){
	//32-bit --> 4-bitx8
	final_index = class_index[4:3] + split_key;
	reg_toupdate_value = slice;	// class_index[2:0]  1 | 2^4 | 2^8 | 2^12 | 2^16 | 2^20 | 2^24 | 2^28
}
action no_slicing(){
	reg_key[15:14] = class_index[1:0];
	final_index = class_index[3:2];
	reg_toupdate_value = 1;	
}
table enable_slicing{
	key = {
		class_index: exact;
		ig_intr_md.resubmit_flag: exact;  // is a resubmit packet? if so, minus secure bit
	}
	actions = {
		slicing2;
		slicing4;
		slicing8;
		no_slicing;
	}
	default_action = no_slicing();
}
action return_class(bit<4> index){
	class_index[3:0] = index;
}
table map_to_distribution{
	key = {
		reg_c_timer1_res: ternary;
	}
	actions = {
		return_class;
	}
}
	
apply {
	@stage(0){
	get_timer.apply();
	check_tcp_table.apply();
	reg_time_key[16:0]= hash0.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.udp.src_port, hdr.udp.dst_port})[16:0];
			
	set_flowkey.apply(); 
	reg_c_timer1_table.apply(); 
	map_to_distribution.apply(); // map IPD to class
	enable_slicing.apply();
	
	reg_class0_w1_table.apply(); 
	reg_class1_w1_table.apply(); 
	reg_class2_w1_table.apply(); 
	reg_class3_w1_table.apply(); 
	reg_class0_w2_table.apply(); 
	reg_class1_w2_table.apply(); 
	reg_class2_w2_table.apply(); 
	reg_class3_w2_table.apply(); 	


	reg_slicing_table.apply();	
	upload_table.apply();	
	resubmit_table.apply();
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
