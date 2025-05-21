cpv(gps_position_loop).
cpv(gps_position_loop, required_component, gps_receiver).
cpv(gps_position_loop, required_component, controller).
cpv(gps_position_loop, required_component, controller).
cpv(gps_position_loop, required_component, esc).
cpv(gps_position_loop, required_component, motor).
cpv(gps_position_loop, entry_component, gps_receiver).
cpv(gps_position_loop, exit_component, motor).
cpv(gps_position_loop, vulnerability, gps_spoofing_vuln).
cpv(gps_position_loop, vulnerability, controller_integrity_vuln).
cpv(gps_position_loop, vulnerability, lack_serial_authentication_vuln).
cpv(gps_position_loop, initial_condition("Position"), "Any").
cpv(gps_position_loop, initial_condition("Heading"), "Any").
cpv(gps_position_loop, initial_condition("Speed"), "Any").
cpv(gps_position_loop, initial_condition("Environment"), "Any").
cpv(gps_position_loop, initial_condition("RemoteController"), "On").
cpv(gps_position_loop, initial_condition("CPSController"), "Idle").
cpv(gps_position_loop, initial_condition("Operating mode"), "Any").
cpv(gps_position_loop, attack_requirement, "GPS Spoof device (e.g., HackRF SDR)").
attack_vector(vector_gps_position_loop_0).
attack_vector(vector_gps_position_loop_0, name, "GPS Spoofing Signal Injection").
attack_signal(signal_gps_position_loop_0).
attack_signal(signal_gps_position_loop_0, src, external_input).
attack_signal(signal_gps_position_loop_0, dst, gps_receiver).
attack_signal(signal_gps_position_loop_0, modality, gps).
attack_vector(vector_gps_position_loop_0, signal, signal_gps_position_loop_0).
attack_vector(vector_gps_position_loop_0, required_access_level, "Remote").
attack_vector(vector_gps_position_loop_0, configuration("duration"), "permanent").
attack_vector(vector_gps_position_loop_0, name, "GPS Spoofing Signal Injection").
cpv(gps_position_loop, attack_vector, vector_gps_position_loop_0).
attack_impact(impact_gps_position_loop_0).
attack_impact(impact_gps_position_loop_0, category, "Deny of Service").
attack_impact(impact_gps_position_loop_0, description, "The CPS’s behavior can be altered in unintended ways, such as stopping mid-sequence, moving intermittently, or executing a sequence not commanded by the operator").
cpv(gps_position_loop, attack_vector, impact_gps_position_loop_0).
cpv(gps_position_loop, exploit_step(0), "Configure the HackRF device and replace the GPS antenna.").
cpv(gps_position_loop, exploit_step(1), "Transmit the spoofed GPS signal using specific commands.").
cpv(gps_position_loop, exploit_step(2), "Connect the RemoteController to a computer via USB.").
cpv(gps_position_loop, exploit_step(3), "Open a terminal emulator or use provided scripts to send commands.").
cpv(gps_position_loop, exploit_step(4), "Input specific control commands").
cpv(gps_position_loop, reference_url, "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV013").
