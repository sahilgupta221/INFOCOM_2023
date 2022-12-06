parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser IngressParser(packet_in        pkt,
    /* User */
    out ingress_headers_t          hdr,
    out ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{

    Checksum() ipv4_checksum;
    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
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
