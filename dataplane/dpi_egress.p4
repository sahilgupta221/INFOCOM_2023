#ifndef _UTIL_
#define _UTIL_

    /***********************  P A R S E R  **************************/

parser TofinoEgressParser(
        packet_in pkt,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}


parser EgressParser(
        packet_in pkt,
    /* User */
    out egress_headers_t          hdr,
    out egress_metadata_t         eg_md,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
    {
    Checksum() ipv4_checksum;
    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition parse_metadata;
    }

    state parse_metadata {
        mirror_h mirror_md = pkt.lookahead<mirror_h>();
        transition select(mirror_md.pkt_type) {
            PKT_TYPE_MIRROR : parse_mirror_tagging_state;
            default : parse_normal_tagging_state;
        }
    }

    state parse_normal_tagging_state {
        eg_md.packet_state = 1;
        transition parse_ethernet;
    }

    state parse_mirror_tagging_state {
        mirror_h mirror_md;
        pkt.extract(mirror_md);
        eg_md.packet_state = 10;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_IPV6 : parse_ipv6;
            default : accept;
        }
    }

//ToDo: add ipv4.len field to move further only if ipv4.len >100 else accept

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        ipv4_checksum.add(hdr.ipv4);
        transition select(hdr.ipv4.total_len) {
           0 .. 100   : accept;
          100 .. 65535 : parse_l4_temp_state;
               default : accept;
        }
    }

    state parse_l4_temp_state {
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.src_port) {
            DNS: parse_app;
            RECIRCULAR_PORT: parse_recirculation;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.dst_port) {
            HTTP: parse_app;
            HTTPS: parse_app;
            RECIRCULAR_PORT: parse_recirculation;
            default: accept;
        }
    }

    state parse_recirculation {
        pkt.extract(hdr.recir);
        transition parse_app;
    }

    state parse_app {
        pkt.extract(hdr.app);
        transition accept;
    }

}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout egress_headers_t                          hdr,
    inout egress_metadata_t                         eg_md,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
    {

    apply {
        // A. Normal packet tagging
        if(hdr.recir.packet_state == 0 && eg_md.packet_state == 1){
        hdr.recir.packet_state = 1;
        }

        // B. Cloned packet tagging
        if(hdr.recir.packet_state == 0 && eg_md.packet_state == 10){
        hdr.recir.packet_state = 10;
        }
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(
        packet_out pkt,
    /* User */
    inout egress_headers_t                       hdr,
    in    egress_metadata_t                      eg_md,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
    {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.recir);
        pkt.emit(hdr.app);
    }
}


#endif /* _UTIL */
