cpv(gps).
cpv(gps, required_component, gps_receiver).
cpv(gps, required_component, px4controller).
cpv(gps, required_component, esc).
cpv(gps, required_component, multi_copter_motor).
cpv(gps, entry_component, gps_receiver).
cpv(gps, exit_component, multi_copter_motor).
cpv(gps, vulnerability, gps_spoofing_vuln).
cpv(gps, vulnerability, px4controller_integrity_vuln).
cpv(gps, initial_condition("Position"), "Any").
cpv(gps, initial_condition("Heading"), "Any").
cpv(gps, initial_condition("Speed"), "None").
cpv(gps, initial_condition("Environment"), "Open Field or Urban Area").
cpv(gps, initial_condition("RemoteController"), "Active").
cpv(gps, initial_condition("CPSController"), "Active").
cpv(gps, initial_condition("Operating mode"), "Any").
cpv(gps, attack_requirement, "GPS signal jammer or spoofer (e.g., HackRF SDR)").
attack_vector(vector_gps_0).
attack_vector(vector_gps_0, name, "GPS Spoofing Signals Injection").
attack_signal(signal_gps_0).
attack_signal(signal_gps_0, src, external_input).
attack_signal(signal_gps_0, dst, gps_receiver).
attack_signal(signal_gps_0, modality, gps_signals).
attack_vector(vector_gps_0, signal, signal_gps_0).
attack_vector(vector_gps_0, required_access_level, "Remote").
attack_vector(vector_gps_0, configuration("duration"), "Permanent").
attack_vector(vector_gps_0, name, "GPS Spoofing Signals Injection").
cpv(gps, attack_vector, vector_gps_0).
attack_impact(impact_gps_0).
attack_impact(impact_gps_0, category, "Control Manipulation").
attack_impact(impact_gps_0, description, "The attacker manipulates the GPS signal to create erroneous localization, causing the drone to deviate from its intended path.").
cpv(gps, attack_vector, impact_gps_0).
cpv(gps, exploit_step(0), "Deploy GPS spoofer near the target's vicinity.").
cpv(gps, exploit_step(1), "Send modified GPS signals targeting the drone's receiver.").
cpv(gps, exploit_step(2), "Observe the manipulated localization output.").
cpv(gps, exploit_step(3), "Guide the drone off its intended trajectory or into dangerous zones.").
cpv(gps, reference_url, "https://www.usenix.org/conference/usenixsecurity22/presentation/zhou-ce").
