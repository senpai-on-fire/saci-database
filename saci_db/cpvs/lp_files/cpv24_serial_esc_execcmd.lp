cpv(esc_execcmd).
cpv(esc_execcmd, required_component, serial).
cpv(esc_execcmd, required_component, esc).
cpv(esc_execcmd, required_component, motor).
cpv(esc_execcmd, entry_component, serial).
cpv(esc_execcmd, exit_component, motor).
cpv(esc_execcmd, vulnerability, lack_serial_authentication_vuln).
cpv(esc_execcmd, initial_condition("Position"), "Any").
cpv(esc_execcmd, initial_condition("Heading"), "Any").
cpv(esc_execcmd, initial_condition("Speed"), "Any").
cpv(esc_execcmd, initial_condition("Environment"), "Any").
cpv(esc_execcmd, initial_condition("BMS"), "On").
cpv(esc_execcmd, initial_condition("ESC"), "On").
cpv(esc_execcmd, initial_condition("Operating mode"), "Any").
cpv(esc_execcmd, attack_requirement, "Computer").
cpv(esc_execcmd, attack_requirement, "USB-TTL Serial Adapter with 3.3v logic").
attack_vector(vector_esc_execcmd_0).
attack_vector(vector_esc_execcmd_0, name, "Serial Get_Info Exec Command Injection").
attack_signal(signal_esc_execcmd_0).
attack_signal(signal_esc_execcmd_0, src, external_input).
attack_signal(signal_esc_execcmd_0, dst, serial).
attack_signal(signal_esc_execcmd_0, modality, serial_commands).
attack_signal(signal_esc_execcmd_0, data, "info").
attack_vector(vector_esc_execcmd_0, signal, signal_esc_execcmd_0).
attack_vector(vector_esc_execcmd_0, required_access_level, "Physical").
attack_vector(vector_esc_execcmd_0, configuration("repetitions"), "1025").
attack_vector(vector_esc_execcmd_0, name, "Serial Get_Info Exec Command Injection").
cpv(esc_execcmd, attack_vector, vector_esc_execcmd_0).
attack_impact(impact_esc_execcmd_0).
attack_impact(impact_esc_execcmd_0, category, "Denial of Control").
attack_impact(impact_esc_execcmd_0, description, "Motors stop spinning").
cpv(esc_execcmd, attack_vector, impact_esc_execcmd_0).
cpv(esc_execcmd, exploit_step(0), "Connect the USB-TTL Serial Adapter to the RC_1 test point on the ESC.").
cpv(esc_execcmd, exploit_step(1), "Send a Serial Command that is longer than the buffer.").
cpv(esc_execcmd, reference_url, "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV007").
