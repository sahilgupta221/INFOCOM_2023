#ifndef _HEADERS_
#define _HEADERS_

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

const bit<8> ORIGINAL_PACKET = 0;
const bit<8> ORIGINAL_RECIRCULATED_PACKET = 1;
const bit<8> CLONED_RECIRCULATED_PACKET = 10;
const bit<8> ORIGINAL_RECIRCULATED_PACKET_PASS = 2;
const bit<8> ORIGINAL_RECIRCULATED_PACKET_FAIL = 3;
const bit<8> CLONED_RECIRCULATED_PACKET_PASS = 4;
const bit<8> CLONED_RECIRCULATED_PACKET_FAIL = 5;
const bit<8> ACCEPT = 4;
const bit<8> REJECT = 5;
const bit<8> RECIRCULATE = 7;

#if __TARGET_TOFINO__ == 1
typedef bit<3> mirror_type_t;
#else
typedef bit<4> mirror_type_t;
#endif

const bit<8> SESSION_ID = 32;
const bit<16> RECIRCULAR_PORT = 5555;
const bit<16> HTTP = 80;
const bit<16> HTTPS = 443;
const mirror_type_t MIRROR_TYPE_I2E = 1;
const bit<16> DNS = 53;
typedef bit<8>  pkt_type_t;
const pkt_type_t PKT_TYPE_MIRROR = 10;
const MirrorId_t ing_mir_ses = 0;
const pkt_type_t pkt_type = 0;


header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    ipv6_addr_t src_addr;
    ipv6_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header recirculation_h {
    bit<16> pattern_state_machine_state; //state of byte matched so far from app layer
    bit<16> accept_state_flag;
    bit<8> let_it_go_register_value;
    bit<8> packet_state; //Classify packet as originally recirculated/cloned recirculated
    bit<16> port_value;
}

header app_h {
    bit<8> byte;
}

header mirror_h {
    pkt_type_t  pkt_type;
}

struct ingress_headers_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    ipv6_h ipv6;
    tcp_h tcp;
    udp_h udp;
    recirculation_h recir;
    app_h app;
}

struct empty_header_t {}

struct empty_metadata_t {}
struct ingress_metadata_t {
    bit<8> packet_state; //Classify packet as originally recirculated/cloned recirculated
    bit<16> pattern_state_machine_state; //state of byte matched so far from app layer
}
struct metadata_t {}
/***********************   **************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct egress_headers_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    ipv6_h ipv6;
    tcp_h tcp;
    udp_h udp;
    recirculation_h recir;
    app_h app;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct egress_metadata_t {
    bit<8> packet_state; //Classify packet as originally recirculated/cloned recirculated
    bit<16> pattern_state_machine_state; //state of byte matched so far from app layer
}


#endif /* _HEADERS_ */
