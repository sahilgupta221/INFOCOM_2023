from netaddr import IPAddress

p4 = bfrt.tna_fsm_dpi.pipe

# This function can clear all the tables and later on other fixed objects
# once bfrt support is added.
def clear_all(verbose=True, batching=True):
    global p4
    global bfrt

    # The order is important. We do want to clear from the top, i.e.
    # delete objects that use other objects, e.g. table entries use
    # selector groups and selector groups use action profile members

    for table_types in (['MATCH_DIRECT', 'MATCH_INDIRECT_SELECTOR'],
                        ['SELECTOR'],
                        ['ACTION_PROFILE']):
        for table in p4.info(return_info=True, print_info=False):
            if table['type'] in table_types:
                if verbose:
                    print("Clearing table {:<40} ... ".
                          format(table['full_name']), end='', flush=True)
                table['node'].clear(batch=batching)
                if verbose:
                    print('Done')

clear_all(verbose=True)

# Update forward table for routing/forwarding
forward_table = p4.Ingress.forward
forward_table.add_with_route(dst_addr=IPAddress('10.0.0.2'),dst_addr_p_length=32,port=2)
forward_table.add_with_route(dst_addr=IPAddress('10.0.0.1'),dst_addr_p_length=32,port=1)

# Update HTTP TCAM table
fsm = p4.Ingress.fsm
fsm.add_with_update_state(pattern_state_machine_state= 0,byte=0x62,new_state= 1,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 0,byte=0x67,new_state= 2,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 0,byte=0x71,new_state= 3,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 0,byte=0x79,new_state= 4,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 0,byte=0x74,new_state= 5,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 1,byte=0x61,new_state= 38,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 2,byte=0x6f,new_state= 29,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 3,byte=0x71,new_state= 9,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 4,byte=0x6f,new_state= 14,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 5,byte=0x6d,new_state= 6,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 6,byte=0x61,new_state= 7,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 7,byte=0x6c,new_state= 8,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 8,byte=0x6c,new_state= 9,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 9,byte=0x2e,new_state= 10,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 10,byte=0x63,new_state= 11,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 11,byte=0x6f,new_state= 12,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 12,byte=0x6d,new_state= 13,is_new_state_a_final_state=1)
fsm.add_with_update_state(pattern_state_machine_state= 14,byte=0x75,new_state= 15,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 15,byte=0x74,new_state= 16,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 16,byte=0x75,new_state= 17,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 17,byte=0x62,new_state= 18,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 18,byte=0x65,new_state= 9,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 29,byte=0x6f,new_state= 30,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 30,byte=0x67,new_state= 31,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 31,byte=0x6c,new_state= 18,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 38,byte=0x69,new_state= 39,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 39,byte=0x64,new_state= 40,is_new_state_a_final_state=0)
fsm.add_with_update_state(pattern_state_machine_state= 40,byte=0x75,new_state= 9,is_new_state_a_final_state=0)


bfrt.complete_operations()

# Final programming
print("""
******************* PROGAMMING RESULTS *****************
""")

print ("Table forward table:")
forward_table.dump(table=True)

print ("Table fsm:")
fsm.dump(table=True)

