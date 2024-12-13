cpv(permanent_compass_spoofing).
cpv(permanent_compass_spoofing, required_component, compass_sensor).
cpv(permanent_compass_spoofing, required_component, controller).
cpv(permanent_compass_spoofing, required_component, controller).
cpv(permanent_compass_spoofing, required_component, steering).
cpv(permanent_compass_spoofing, entry_component, compass_sensor).
cpv(permanent_compass_spoofing, exit_component, motor).
cpv(permanent_compass_spoofing, vulnerability, compass_spoofing_vuln).
cpv(permanent_compass_spoofing, vulnerability, controller_integrity_vuln).
cpv(permanent_compass_spoofing, initial_condition("Position"), "Any").
cpv(permanent_compass_spoofing, initial_condition("Heading"), "Any").
cpv(permanent_compass_spoofing, initial_condition("Speed"), "Any").
cpv(permanent_compass_spoofing, initial_condition("Environment"), "Any").
cpv(permanent_compass_spoofing, initial_condition("RemoteController"), "On").
cpv(permanent_compass_spoofing, initial_condition("CPSController"), "Moving").
cpv(permanent_compass_spoofing, initial_condition("Operating mode"), "Mission").
cpv(permanent_compass_spoofing, attack_requirement, "Magnet with adequate shapes and dimensions").
attack_vector(vector_permanent_compass_spoofing_0).
attack_vector(vector_permanent_compass_spoofing_0, name, "Magnetic Signals Interference").
attack_signal(signal_permanent_compass_spoofing_0).
attack_signal(signal_permanent_compass_spoofing_0, src, external_input).
attack_signal(signal_permanent_compass_spoofing_0, dst, compass_sensor).
attack_signal(signal_permanent_compass_spoofing_0, modality, magnetic).
attack_vector(vector_permanent_compass_spoofing_0, signal, signal_permanent_compass_spoofing_0).
attack_vector(vector_permanent_compass_spoofing_0, required_access_level, "Physical").
attack_vector(vector_permanent_compass_spoofing_0, configuration("duration"), "permanent").
attack_vector(vector_permanent_compass_spoofing_0, name, "Magnetic Signals Interference").
cpv(permanent_compass_spoofing, attack_vector, vector_permanent_compass_spoofing_0).
attack_impact(impact_permanent_compass_spoofing_0).
attack_impact(impact_permanent_compass_spoofing_0, category, "Loss of control").
attack_impact(impact_permanent_compass_spoofing_0, description, "CPS drives in circles without stopping").
cpv(permanent_compass_spoofing, attack_vector, impact_permanent_compass_spoofing_0).
cpv(permanent_compass_spoofing, exploit_step(0), "Prepare a powerful magnet with adequate shapes and dimensions.").
cpv(permanent_compass_spoofing, exploit_step(1), "Install the magnet on top of the compass.").
cpv(permanent_compass_spoofing, exploit_step(2), "Until observing change in the compass readings, keep doing the following: Point the CPS device at a different direction then install the magnet on top of the compass.").
cpv(permanent_compass_spoofing, exploit_step(3), "Rotate the CPS device and observe that the compass readings do not significantly change as the CPS rotates.").
cpv(permanent_compass_spoofing, reference_url, "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV006").
