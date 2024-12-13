cpv(overflow).
cpv(overflow, required_component, serial).
cpv(overflow, required_component, esc).
cpv(overflow, required_component, motor).
cpv(overflow, entry_component, serial).
cpv(overflow, exit_component, motor).
cpv(overflow, vulnerability, lack_serial_authentication_vuln).
cpv(overflow, initial_condition("Position"), "Any").
cpv(overflow, initial_condition("Heading"), "Any").
cpv(overflow, initial_condition("Speed"), "Any").
cpv(overflow, initial_condition("Environment"), "Any").
cpv(overflow, initial_condition("BMS"), "On").
cpv(overflow, initial_condition("ESC"), "On").
cpv(overflow, initial_condition("Operating mode"), "Any").
cpv(overflow, attack_requirement, "Computer").
cpv(overflow, attack_requirement, "USB-TTL Serial Adapter with 3.3v logic").
attack_vector(vector_overflow_0).
attack_vector(vector_overflow_0, name, "Serial ASCII_Characters Command Injection").
attack_signal(signal_overflow_0).
attack_signal(signal_overflow_0, src, external_input).
attack_signal(signal_overflow_0, dst, serial).
attack_signal(signal_overflow_0, modality, serial_commands).
attack_signal(signal_overflow_0, data, "ASCII Characters").
attack_vector(vector_overflow_0, signal, signal_overflow_0).
attack_vector(vector_overflow_0, required_access_level, "Physical").
attack_vector(vector_overflow_0, configuration("length"), "1025").
attack_vector(vector_overflow_0, name, "Serial ASCII_Characters Command Injection").
cpv(overflow, attack_vector, vector_overflow_0).
attack_impact(impact_overflow_0).
attack_impact(impact_overflow_0, category, "Denial of Control").
attack_impact(impact_overflow_0, description, "Motors stop spinning").
cpv(overflow, attack_vector, impact_overflow_0).
cpv(overflow, exploit_step(0), "Connect the USB-TTL Serial Adapter to the RC_1 test point on the ESC.").
cpv(overflow, exploit_step(1), "Send a Serial Command that is longer than the buffer.").
cpv(overflow, reference_url, "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV006").
