cpv(gps_position_static).
cpv(gps_position_static, required_component, gps_receiver).
cpv(gps_position_static, required_component, controller).
cpv(gps_position_static, required_component, controller).
cpv(gps_position_static, required_component, esc).
cpv(gps_position_static, required_component, motor).
cpv(gps_position_static, entry_component, gps_receiver).
cpv(gps_position_static, exit_component, motor).
cpv(gps_position_static, vulnerability, gps_spoofing_vuln).
cpv(gps_position_static, vulnerability, controller_integrity_vuln).
cpv(gps_position_static, initial_condition("Position"), "Any").
cpv(gps_position_static, initial_condition("Heading"), "Any").
cpv(gps_position_static, initial_condition("Speed"), "Any").
cpv(gps_position_static, initial_condition("Environment"), "Any").
cpv(gps_position_static, initial_condition("RemoteController"), "On").
cpv(gps_position_static, initial_condition("CPSController"), "Moving").
cpv(gps_position_static, initial_condition("Operating mode"), "Mission").
cpv(gps_position_static, attack_requirement, "GPS Spoof device (e.g., HackRF SDR)").
attack_vector(vector_gps_position_static_0).
attack_vector(vector_gps_position_static_0, name, "GPS Spoofing Signals Injection").
attack_signal(signal_gps_position_static_0).
attack_signal(signal_gps_position_static_0, src, external_input).
attack_signal(signal_gps_position_static_0, dst, gps_receiver).
attack_signal(signal_gps_position_static_0, modality, gps_signals).
attack_vector(vector_gps_position_static_0, signal, signal_gps_position_static_0).
attack_vector(vector_gps_position_static_0, required_access_level, "Remote").
attack_vector(vector_gps_position_static_0, configuration("duration"), "permanent").
attack_vector(vector_gps_position_static_0, name, "GPS Spoofing Signals Injection").
cpv(gps_position_static, attack_vector, vector_gps_position_static_0).
attack_impact(impact_gps_position_static_0).
attack_impact(impact_gps_position_static_0, category, "Loss of control").
attack_impact(impact_gps_position_static_0, description, "CPS drives in circles without stopping").
cpv(gps_position_static, attack_vector, impact_gps_position_static_0).
cpv(gps_position_static, exploit_step(0), "Configure the HackRF device and replace the GPS antenna.").
cpv(gps_position_static, exploit_step(1), "Transmit the spoofed GPS signal using specific commands.").
cpv(gps_position_static, reference_url, "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV007").
