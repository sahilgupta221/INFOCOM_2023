//SwitchIngress code

control Ingress(
    /* User */
    inout ingress_headers_t                       hdr,
    inout ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
// Declare register that will pass results from cloned analyzed packet to original recirculated packet
// temparary variable to store value.
bit<32> let_it_go_register_key=0;
bit<8> let_it_go_register_value=0;
bit<16> port_value=0;
bit<8> accept_state_flag=0;
bit<2> fsm_flag=0;

//Registers
    Register<bit<8>, bit<32>>(16384*35)  let_it_go_register;
//Register<bit<8>>(size=4096, initial_value=7) my_reg; or make 0 as RECIRCULATE value
//    Register<bit<16>, bit<32>>(400000000) port_register;
//    Register<bit<8>, bit<32>>(400000000) let_it_go_register;

    RegisterAction<bit<8>, bit<32>, bit<8>>(let_it_go_register) let_it_go_read = {
        void apply(inout bit<8> reg_value, out bit<8> result) {
            result = reg_value;
        }
    };

    RegisterAction<bit<8>, bit<32>, bit<8>>(let_it_go_register) let_it_go_accept = {
        void apply(inout bit<8> reg_value) {
            reg_value = ACCEPT;
        }
    };

    RegisterAction<bit<8>, bit<32>, bit<8>>(let_it_go_register) let_it_go_reject = {
        void apply(inout bit<8> reg_value) {
            reg_value = REJECT;
        }
    };


//Hash to compute the key (location) where let_it_go register value will be stored.
Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_1;
Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_2;

//Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_2;
// Forwarding table and action
    action route(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        ig_dprsr_md.drop_ctl = 0;
        }
    action nop() {}

    action drop() {
        ig_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    action do_recirculate(){
    ig_tm_md.ucast_egress_port = 68;
    }

    table forward {
        key = {
            hdr.ipv4.dst_addr : lpm;
        }

        actions = {
            route;
            drop;
            nop;
        }
        const default_action = drop;
        size = 1024;
    }

// FSM table and action
    action update_state(bit<16> new_state, bit<8> is_new_state_a_final_state){
    	hdr.recir.pattern_state_machine_state = new_state;
        accept_state_flag = is_new_state_a_final_state;
    }
    action reset_state(){
    	hdr.recir.pattern_state_machine_state = 0;
    }

    table fsm {
        key = {
	     hdr.recir.pattern_state_machine_state:exact;
            hdr.app.byte: exact;
        }

        actions = {
            update_state;
	        reset_state;
            nop;
        }
        const default_action = reset_state();
        size = 1024;
    }


			action original_tcp_packet_action(){
			// A. Mirror
            ig_dprsr_md.mirror_type = MIRROR_TYPE_I2E;
			// B. Recirculate
            do_recirculate();
			// C. Validate recirculated header
            hdr.recir.setValid();
            hdr.recir.packet_state=0;
            hdr.recir.pattern_state_machine_state=0;
			hdr.recir.let_it_go_register_value = RECIRCULATE;

			// D. Set TCP PORT to RECIRCULAR_PORT
			// Store the TCP port value in port register
			hdr.recir.port_value = hdr.tcp.dst_port;
            hdr.tcp.dst_port = 5555;
			}

			action original_udp_packet_action(){
			// A. Mirror
            ig_dprsr_md.mirror_type = MIRROR_TYPE_I2E;
			// B. Recirculate
            do_recirculate();
			// C. Validate recirculated header
            hdr.recir.setValid();
            hdr.recir.packet_state=0;
            hdr.recir.pattern_state_machine_state=0;
			hdr.recir.let_it_go_register_value = RECIRCULATE;
			
			// D. Set UDP PORT to RECIRCULAR_PORT
			// Store the UDP port value in port register
            hdr.recir.port_value = hdr.udp.src_port;
            hdr.udp.src_port = 5555;
			}


			action original_recirculated_tcp_packet_recirculate_action(){
			//Check result of the clone packet from let_it_go_register.
			hdr.recir.let_it_go_register_value = let_it_go_read.execute(let_it_go_register_key);
			//hdr.recir.let_it_go_register_value = let_it_go_register.read(let_it_go_register_key);
			do_recirculate();            			
			}
			
			action original_recirculated_tcp_packet_accept_action(){
            hdr.tcp.dst_port = hdr.recir.port_value;
            hdr.recir.setInvalid();			
			}
			
			action original_recirculated_tcp_packet_reject_action(){
			drop();
			}

            
			action original_recirculated_udp_packet_recirculate_action(){
			// Check result of the clone packet from let_it_go_register.
            hdr.recir.let_it_go_register_value = let_it_go_read.execute(let_it_go_register_key);
			//hdr.recir.let_it_go_register_value = let_it_go_register.read(let_it_go_register_key);
			do_recirculate();			
			}
			
			action original_recirculated_udp_packet_accept_action(){
            hdr.udp.src_port = hdr.recir.port_value;
            hdr.recir.setInvalid();			
			}
			
			action original_recirculated_udp_packet_reject_action(){
			drop();
			}			

            
			action recirculated_mirrored_tcp_packet_recirculate_action(){
			// If app is valid then check FSM table for pattern matching at app layer
			fsm_flag = 1;
			}
			
			action recirculated_mirrored_tcp_packet_accept_action(){
            let_it_go_accept.execute(let_it_go_register_key);
			//let_it_go_register.write(let_it_go_register_key,ACCEPT);
			drop();
			}
			
			action recirculated_mirrored_tcp_packet_reject_action(){
            let_it_go_reject.execute(let_it_go_register_key);
            //let_it_go_register.write(let_it_go_register_key,REJECT);
			drop();
			}
			
			
            action recirculated_mirrored_udp_packet_recirculate_action(){
			//If app is valid then check FSM table for pattern matching at app layer
			fsm_flag = 1;
			}
			
			
            action recirculated_mirrored_udp_packet_accept_action(){
            let_it_go_accept.execute(let_it_go_register_key);
			//let_it_go_register.write(let_it_go_register_key,ACCEPT);
			drop();
			}
			
	        action recirculated_mirrored_udp_packet_reject_action(){
            let_it_go_reject.execute(let_it_go_register_key);
            //let_it_go_register.write(let_it_go_register_key,REJECT);
			drop();
			}

    table first_level_table {
        key = {
/*																					hdr.udp.isValid()	hdr.tcp.isValid()	hdr.app.isValid()	hdr.recir.isValid()	hdr.recir.packet_state:ternary	hdr.recir.let_it_go_register_value:ternary	Action
	Original TCP:																false	true	true	false	_	_	original_tcp_packet_action;
	Original UDP:																true	false	true	false	_	_	original_udp_packet_action;

	Original TCP recirculated: (RECIRCULATE)						false	true	true	true	1	RECIRCULATE	original_recirculated_tcp_packet_recirculate_action;
	Original TCP recirculated: (ACCEPT)								false	true	true	true	1	ACCEPT	original_recirculated_tcp_packet_accept_action;
	Original TCP recirculated: (REJECT)								false	true	true	true	1	REJECT	original_recirculated_tcp_packet_reject_action;

	Original UDP recirculated: (RECIRCULATE)						true	false	true	true	1	RECIRCULATE	original_recirculated_udp_packet_recirculate_action;
	Original UDP recirculated: (ACCEPT)								true	false	true	true	1	ACCEPT	original_recirculated_udp_packet_accept_action;
	Original UDP recirculated: (REJECT)								true	false	true	true	1	REJECT	original_recirculated_udp_packet_reject_action;

	Recirculated Mirrored TCP : (RECIRCULATE)					false	true	true	true	10	RECIRCULATE	recirculated_mirrored_tcp_packet_recirculate_action;
	Recirculated Mirrored TCP: (ACCEPT)							false	true	false	true	10	RECIRCULATE	recirculated_mirrored_tcp_packet_accept_action;
	Recirculated Mirrored TCP: (REJECT with app header)		false	true	true	true	10	REJECT	recirculated_mirrored_tcp_packet_reject_action;
	Recirculated Mirrored TCP: (REJECT without app header)	false	true	false	true	10	REJECT	recirculated_mirrored_tcp_packet_reject_action;

	Recirculated Mirrored UDP : (RECIRCULATE)					true	false	true	true	10	RECIRCULATE	recirculated_mirrored_udp_packet_recirculate_action;
	Recirculated Mirrored UDP: (ACCEPT)							true	false	false	true	10	RECIRCULATE	recirculated_mirrored_udp_packet_accept_action;
	Recirculated Mirrored UDP: (REJECT with app header)		true	false	true	true	10	REJECT	recirculated_mirrored_udp_packet_reject_action;
	Recirculated Mirrored UDP: (REJECT without app header)true	false	false	true	10	REJECT	recirculated_mirrored_udp_packet_reject_action;
*/

		hdr.udp.isValid():exact;
		hdr.tcp.isValid():exact;
		hdr.app.isValid():exact;
		hdr.recir.isValid():exact;
		hdr.recir.packet_state:ternary;
		hdr.recir.let_it_go_register_value:ternary;
        }
        actions = {
            original_tcp_packet_action;
            original_udp_packet_action;

			original_recirculated_tcp_packet_recirculate_action;
			original_recirculated_tcp_packet_accept_action;
			original_recirculated_tcp_packet_reject_action;

			original_recirculated_udp_packet_recirculate_action;
			original_recirculated_udp_packet_accept_action;
			original_recirculated_udp_packet_reject_action;

			recirculated_mirrored_tcp_packet_recirculate_action;
			recirculated_mirrored_tcp_packet_accept_action;
			recirculated_mirrored_tcp_packet_reject_action;

            recirculated_mirrored_udp_packet_recirculate_action;
            recirculated_mirrored_udp_packet_accept_action;
	        recirculated_mirrored_udp_packet_reject_action;
            nop;
        }

        const entries = {
            (false,	true,	true,	false,	_,	_) :
            original_tcp_packet_action();
            (true,	false,	true,	false,	_,	_) :
            original_udp_packet_action();
            (false,	true,	true,	true,	1,	RECIRCULATE) :
			original_recirculated_tcp_packet_recirculate_action();
            (false,	true,	true,	true,	1,	ACCEPT) :
			original_recirculated_tcp_packet_accept_action();
            (false,	true,	true,	true,	1,	REJECT) :
			original_recirculated_tcp_packet_reject_action();
            (true,	false,	true,	true,	1,	RECIRCULATE) :
			original_recirculated_udp_packet_recirculate_action();
            (true,	false,	true,	true,	1,	ACCEPT) :
			original_recirculated_udp_packet_accept_action();
            (true,	false,	true,	true,	1,	REJECT) :
			original_recirculated_udp_packet_reject_action();
            (false,	true,	true,	true,	10,	RECIRCULATE) :
			recirculated_mirrored_tcp_packet_recirculate_action();
            (false,	true,	false,	true,	10,	RECIRCULATE) :
			recirculated_mirrored_tcp_packet_accept_action();
            (false,	true,	true,	true,	10,	REJECT) :
			recirculated_mirrored_tcp_packet_reject_action();
            (false,	true,	false,	true,	10,	REJECT) :
			recirculated_mirrored_tcp_packet_reject_action();

            (true,	false,	true,	true,	10,	RECIRCULATE) :
            recirculated_mirrored_udp_packet_recirculate_action();
            (true,	false,	false,	true,	10,	RECIRCULATE) :
            recirculated_mirrored_udp_packet_accept_action();
            (true,	false,	true,	true,	10,	REJECT) :
	        recirculated_mirrored_udp_packet_reject_action();
            (true,	false,	false,	true,	10,	REJECT) :
	        recirculated_mirrored_udp_packet_reject_action();
        }

        const default_action = nop();
        size = 1024;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            forward.apply();

			if(hdr.tcp.isValid()){
		    // Find Register index/key/location calculation to store the let_it_go flag (Hash)
			let_it_go_register_key = hash_1.get(
			{
				hdr.ipv4.src_addr,
				hdr.ipv4.dst_addr,
				hdr.tcp.src_port,
				hdr.tcp.dst_port,
				hdr.ipv4.total_len,
				hdr.ipv4.identification
				})[31:0];
		    }
			else if(hdr.udp.isValid()){
			// Find Register index/key/location calculation to store the let_it_go flag (Hash)
			let_it_go_register_key = hash_2.get(
			{
			hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,
            hdr.udp.src_port,
            hdr.udp.dst_port
            })[31:0];
			}

			first_level_table.apply();

	        if (fsm_flag == 1){
            fsm.apply();
			hdr.recir.let_it_go_register_value = accept_state_flag;
			do_recirculate();
			hdr.recir.setInvalid();
            }
        }
    }
}
