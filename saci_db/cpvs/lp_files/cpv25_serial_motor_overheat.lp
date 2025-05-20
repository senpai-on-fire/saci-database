cpv(overheating).
cpv(overheating, required_component, serial).
cpv(overheating, required_component, esc).
cpv(overheating, required_component, motor).
cpv(overheating, entry_component, serial).
cpv(overheating, exit_component, motor).
cpv(overheating, vulnerability, lack_serial_authentication_vuln).
cpv(overheating, initial_condition("Position"), "Any").
cpv(overheating, initial_condition("Heading"), "Any").
cpv(overheating, initial_condition("Speed"), "Any").
cpv(overheating, initial_condition("Environment"), "Any").
cpv(overheating, initial_condition("BMS"), "On").
cpv(overheating, initial_condition("ESC"), "On").
cpv(overheating, initial_condition("Operating mode"), "Any").
cpv(overheating, attack_requirement, "Computer").
cpv(overheating, attack_requirement, "USB-TTL Serial Adapter with 3.3v logic").
attack_vector(vector_overheating_0).
attack_vector(vector_overheating_0, name, "Serial Duty_speed_up Command Injection").
attack_signal(signal_overheating_0).
attack_signal(signal_overheating_0, src, external_input).
attack_signal(signal_overheating_0, dst, serial).
attack_signal(signal_overheating_0, modality, serial_commands).
attack_signal(signal_overheating_0, data, "set duty_spup 100").
attack_vector(vector_overheating_0, signal, signal_overheating_0).
attack_vector(vector_overheating_0, required_access_level, "Physical").
attack_vector(vector_overheating_0, name, "Serial Duty_speed_up Command Injection").
cpv(overheating, attack_vector, vector_overheating_0).
attack_impact(impact_overheating_0).
attack_impact(impact_overheating_0, category, "Damage to Property").
attack_impact(impact_overheating_0, description, "Motors will overheat").
cpv(overheating, attack_vector, impact_overheating_0).
cpv(overheating, exploit_step(0), "Connect the USB-TTL Serial Adapter to the RC_1 test point on the ESC.").
cpv(overheating, exploit_step(1), "Send a Serial Command that sets Duty Cycle during speed up to 100.").
cpv(overheating, reference_url, "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV008").
cpv(overheating, reference_url, "https://github.com/neoxic/ESCape32/wiki/Configuration#cli-command-line-interface").
