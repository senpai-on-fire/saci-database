cpv(mavlink_disarm).
cpv(mavlink_disarm, required_component, mavlink).
cpv(mavlink_disarm, required_component, px4controller).
cpv(mavlink_disarm, required_component, esc).
cpv(mavlink_disarm, required_component, multi_copter_motor).
cpv(mavlink_disarm, entry_component, gcs_telemetry).
cpv(mavlink_disarm, exit_component, multi_copter_motor).
cpv(mavlink_disarm, vulnerability, lack_wifi_authentication_vuln).
cpv(mavlink_disarm, vulnerability, mavlink_vuln01).
cpv(mavlink_disarm, initial_condition("Position"), "Any").
cpv(mavlink_disarm, initial_condition("Heading"), "Any").
cpv(mavlink_disarm, initial_condition("Speed"), "Any (>0)").
cpv(mavlink_disarm, initial_condition("Environment"), "Any").
cpv(mavlink_disarm, initial_condition("RemoteController"), "On").
cpv(mavlink_disarm, initial_condition("CPSController"), "Moving").
cpv(mavlink_disarm, initial_condition("Operating mode"), "flying").
cpv(mavlink_disarm, attack_requirement, "Computer").
cpv(mavlink_disarm, attack_requirement, "namp").
cpv(mavlink_disarm, attack_requirement, "mavproxy").
attack_vector(vector_mavlink_disarm_0).
attack_vector(vector_mavlink_disarm_0, name, "MavLink Packets Injection").
attack_signal(signal_mavlink_disarm_0).
attack_signal(signal_mavlink_disarm_0, src, external_input).
attack_signal(signal_mavlink_disarm_0, dst, gcs_telemetry).
attack_signal(signal_mavlink_disarm_0, modality, network_packets).
attack_vector(vector_mavlink_disarm_0, signal, signal_mavlink_disarm_0).
attack_vector(vector_mavlink_disarm_0, required_access_level, "Proximity").
attack_vector(vector_mavlink_disarm_0, configuration("protocol"), "UDP").
attack_vector(vector_mavlink_disarm_0, configuration("port"), "14550").
attack_vector(vector_mavlink_disarm_0, configuration("command"), "disarm").
attack_vector(vector_mavlink_disarm_0, name, "MavLink Packets Injection").
cpv(mavlink_disarm, attack_vector, vector_mavlink_disarm_0).
attack_impact(impact_mavlink_disarm_0).
attack_impact(impact_mavlink_disarm_0, category, "Physical Impact").
attack_impact(impact_mavlink_disarm_0, description, "The CPS crashes into the ground").
cpv(mavlink_disarm, attack_vector, impact_mavlink_disarm_0).
cpv(mavlink_disarm, exploit_step(0), "1. Identify the IP addresses and ports of the controller and the CPS").
cpv(mavlink_disarm, exploit_step(1), "2. Perform ARP spoofing").
cpv(mavlink_disarm, exploit_step(2), "3. Send a DISARM MAVLink command").
cpv(mavlink_disarm, reference_url, "add alink the video we have").
