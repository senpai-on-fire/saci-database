cpv(discharge).
cpv(discharge, required_component, serial).
cpv(discharge, required_component, esc).
cpv(discharge, required_component, bms).
cpv(discharge, required_component, battery).
cpv(discharge, entry_component, serial).
cpv(discharge, exit_component, battery).
cpv(discharge, vulnerability, lack_serial_authentication_vuln).
cpv(discharge, initial_condition("Position"), "Any").
cpv(discharge, initial_condition("Heading"), "Any").
cpv(discharge, initial_condition("Speed"), "Any").
cpv(discharge, initial_condition("Environment"), "Any").
cpv(discharge, initial_condition("BMS"), "On").
cpv(discharge, initial_condition("ESC"), "On").
cpv(discharge, initial_condition("Operating mode"), "Any").
cpv(discharge, attack_requirement, "Computer").
cpv(discharge, attack_requirement, "USB-TTL Serial Adapter with 3.3v logic").
attack_vector(vector_discharge_0).
attack_vector(vector_discharge_0, name, "Serial Prot_Cells Discharge Command Injection").
attack_signal(signal_discharge_0).
attack_signal(signal_discharge_0, src, external_input).
attack_signal(signal_discharge_0, dst, serial).
attack_signal(signal_discharge_0, modality, serial_commands).
attack_signal(signal_discharge_0, data, "set prot_cells 1").
attack_vector(vector_discharge_0, signal, signal_discharge_0).
attack_vector(vector_discharge_0, required_access_level, "Physical").
attack_vector(vector_discharge_0, name, "Serial Prot_Cells Discharge Command Injection").
cpv(discharge, attack_vector, vector_discharge_0).
attack_impact(impact_discharge_0).
attack_impact(impact_discharge_0, category, "Damage to Property").
attack_impact(impact_discharge_0, description, "ESC will not limit battery discharge").
cpv(discharge, attack_vector, impact_discharge_0).
cpv(discharge, exploit_step(0), "Connect the USB-TTL Serial Adapter to the RC_1 test point on the ESC.").
cpv(discharge, exploit_step(1), "Send the Serial Command 'set prot_cells 1' to the ESC.").
cpv(discharge, reference_url, "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV005").
cpv(discharge, reference_url, "https://github.com/neoxic/ESCape32/wiki/Configuration#cli-command-line-interface").
