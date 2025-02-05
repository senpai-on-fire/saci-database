cpv(icmp_flooding).
cpv(icmp_flooding, required_component, icmp).
cpv(icmp_flooding, required_component, px4controller).
cpv(icmp_flooding, required_component, esc).
cpv(icmp_flooding, required_component, multi_copter_motor).
cpv(icmp_flooding, entry_component, icmp).
cpv(icmp_flooding, exit_component, multi_copter_motor).
cpv(icmp_flooding, vulnerability, lack_wifi_authentication_vuln).
cpv(icmp_flooding, vulnerability, icmp_flood_vuln).
cpv(icmp_flooding, initial_condition("Position"), "Any").
cpv(icmp_flooding, initial_condition("Heading"), "Any").
cpv(icmp_flooding, initial_condition("Speed"), "Any (>0)").
cpv(icmp_flooding, initial_condition("Environment"), "Any").
cpv(icmp_flooding, initial_condition("RemoteController"), "On").
cpv(icmp_flooding, initial_condition("CPSController"), "Moving").
cpv(icmp_flooding, initial_condition("Operating mode"), "Manual").
cpv(icmp_flooding, attack_requirement, "ComputerWIFI card with monitor modeAircrack-ng software").
attack_vector(vector_icmp_flooding_0).
attack_vector(vector_icmp_flooding_0, name, "ICMP Packets Injection").
attack_signal(signal_icmp_flooding_0).
attack_signal(signal_icmp_flooding_0, src, external_input).
attack_signal(signal_icmp_flooding_0, dst, icmp).
attack_signal(signal_icmp_flooding_0, modality, network_packets).
attack_vector(vector_icmp_flooding_0, signal, signal_icmp_flooding_0).
attack_vector(vector_icmp_flooding_0, required_access_level, "Proximity").
attack_vector(vector_icmp_flooding_0, configuration("protocol"), "UDP").
attack_vector(vector_icmp_flooding_0, configuration("port"), "5556").
attack_vector(vector_icmp_flooding_0, name, "ICMP Packets Injection").
cpv(icmp_flooding, attack_vector, vector_icmp_flooding_0).
attack_impact(impact_icmp_flooding_0).
attack_impact(impact_icmp_flooding_0, category, "Denial of control").
attack_impact(impact_icmp_flooding_0, description, "The user can not control the CPS").
cpv(icmp_flooding, attack_vector, impact_icmp_flooding_0).
cpv(icmp_flooding, exploit_step(0), "Set the Wi-Fi card into monitor mode and find the BSSID and channel number for the CPS's Wi-Fi network.").
cpv(icmp_flooding, exploit_step(1), "join the network").
cpv(icmp_flooding, exploit_step(2), "Flood the CPS with TCP SYN on port UDP 5556").
cpv(icmp_flooding, reference_url, "https://link.springer.com/article/10.1007/s11416-011-0158-4").
