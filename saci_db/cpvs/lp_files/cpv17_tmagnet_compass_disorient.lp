cpv(temporary_compass_spoofing).
cpv(temporary_compass_spoofing, required_component, compass_sensor).
cpv(temporary_compass_spoofing, required_component, controller).
cpv(temporary_compass_spoofing, required_component, controller).
cpv(temporary_compass_spoofing, required_component, steering).
cpv(temporary_compass_spoofing, entry_component, compass_sensor).
cpv(temporary_compass_spoofing, exit_component, motor).
cpv(temporary_compass_spoofing, vulnerability, compass_spoofing_vuln).
cpv(temporary_compass_spoofing, vulnerability, type).
cpv(temporary_compass_spoofing, initial_condition("Position"), "Any").
cpv(temporary_compass_spoofing, initial_condition("Heading"), "Any").
cpv(temporary_compass_spoofing, initial_condition("Speed"), "Any").
cpv(temporary_compass_spoofing, initial_condition("Environment"), "Any").
cpv(temporary_compass_spoofing, initial_condition("RemoteController"), "On").
cpv(temporary_compass_spoofing, initial_condition("CPSController"), "Moving").
cpv(temporary_compass_spoofing, initial_condition("Operating mode"), "Mission").
cpv(temporary_compass_spoofing, attack_requirement, "Magnet with adequate shapes and dimensions").
attack_vector(vector_temporary_compass_spoofing_0).
attack_vector(vector_temporary_compass_spoofing_0, name, "Magnetic Signals Interference").
attack_signal(signal_temporary_compass_spoofing_0).
attack_signal(signal_temporary_compass_spoofing_0, src, external_input).
attack_signal(signal_temporary_compass_spoofing_0, dst, compass_sensor).
attack_signal(signal_temporary_compass_spoofing_0, modality, magnetic).
attack_vector(vector_temporary_compass_spoofing_0, signal, signal_temporary_compass_spoofing_0).
attack_vector(vector_temporary_compass_spoofing_0, required_access_level, "Physical").
attack_vector(vector_temporary_compass_spoofing_0, configuration("duration"), "10 sec").
attack_vector(vector_temporary_compass_spoofing_0, name, "Magnetic Signals Interference").
cpv(temporary_compass_spoofing, attack_vector, vector_temporary_compass_spoofing_0).
attack_impact(impact_temporary_compass_spoofing_0).
attack_impact(impact_temporary_compass_spoofing_0, category, "Loss of control").
attack_impact(impact_temporary_compass_spoofing_0, description, "CPS drives in circles without stopping").
cpv(temporary_compass_spoofing, attack_vector, impact_temporary_compass_spoofing_0).
attack_impact(impact_temporary_compass_spoofing_1).
attack_impact(impact_temporary_compass_spoofing_1, category, "Loss of control").
attack_impact(impact_temporary_compass_spoofing_1, description, "over/under steer of the desired turning angle").
cpv(temporary_compass_spoofing, attack_vector, impact_temporary_compass_spoofing_1).
cpv(temporary_compass_spoofing, exploit_step(0), "Prepare a powerful magnet with adequate shapes and dimensions.").
cpv(temporary_compass_spoofing, exploit_step(1), "Install the magnet on top of the compass.").
cpv(temporary_compass_spoofing, exploit_step(2), "Until observing change in the compass readings, keep doing the following: Point the CPS device at a different direction then install the magnet on top of the compass.Leave the magnet in place for at least 10 seconds.").
cpv(temporary_compass_spoofing, exploit_step(3), "Remove the magnet.").
cpv(temporary_compass_spoofing, exploit_step(4), "Rotate the CPS 45 degrees in either direction and observe that the compass readings do not significantly change as the CPS rotates.Rotate the CPS 180 degrees from the original heading. The compass readings should either not significantly change or not change until near 180 degrees.").
cpv(temporary_compass_spoofing, reference_url, "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV007").
