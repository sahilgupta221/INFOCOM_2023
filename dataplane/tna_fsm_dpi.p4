#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "dpi_headers.p4" //All macros and header definations
#include "dpi_ingress_parser.p4" //Switch ingress parser
#include "dpi_ingress_deparser.p4" //Switch deparser logic
#include "ingress_control_block_ultimate.p4" //Switch ingress control block
#include "dpi_egress.p4" //Conplete Switch egress pipeline

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
