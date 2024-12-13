cpv(wi_fi_deauth_dos).
cpv(wi_fi_deauth_dos, required_component, wifi).
cpv(wi_fi_deauth_dos, required_component, web_server).
cpv(wi_fi_deauth_dos, required_component, controller).
cpv(wi_fi_deauth_dos, required_component, controller).
cpv(wi_fi_deauth_dos, required_component, esc).
cpv(wi_fi_deauth_dos, required_component, motor).
cpv(wi_fi_deauth_dos, entry_component, wifi).
cpv(wi_fi_deauth_dos, exit_component, motor).
cpv(wi_fi_deauth_dos, vulnerability, wi_fi_deauth_vuln).
cpv(wi_fi_deauth_dos, initial_condition("Position"), "Any").
cpv(wi_fi_deauth_dos, initial_condition("Heading"), "Any").
cpv(wi_fi_deauth_dos, initial_condition("Speed"), "Any (>0)").
cpv(wi_fi_deauth_dos, initial_condition("Environment"), "Any").
cpv(wi_fi_deauth_dos, initial_condition("RemoteController"), "On").
cpv(wi_fi_deauth_dos, initial_condition("CPSController"), "Moving").
cpv(wi_fi_deauth_dos, initial_condition("Operating mode"), "Manual").
cpv(wi_fi_deauth_dos, attack_requirement, "ComputerWIFI card with monitor modeAircrack-ng software").
cpv(wi_fi_deauth_dos, attack_requirement, "WIFI Credentials").
attack_vector(vector_wi_fi_deauth_dos_0).
attack_vector(vector_wi_fi_deauth_dos_0, name, "Deauthentification Wifi Packets Injection").
attack_signal(signal_wi_fi_deauth_dos_0).
attack_signal(signal_wi_fi_deauth_dos_0, src, external_input).
attack_signal(signal_wi_fi_deauth_dos_0, dst, wifi).
attack_signal(signal_wi_fi_deauth_dos_0, modality, network_packets).
attack_vector(vector_wi_fi_deauth_dos_0, signal, signal_wi_fi_deauth_dos_0).
attack_vector(vector_wi_fi_deauth_dos_0, required_access_level, "Proximity").
attack_vector(vector_wi_fi_deauth_dos_0, configuration("BSSID"), "FuelSource Wifi").
attack_vector(vector_wi_fi_deauth_dos_0, configuration("interface_name"), "wireless").
attack_vector(vector_wi_fi_deauth_dos_0, configuration("other args"), "-0 0 -a").
attack_vector(vector_wi_fi_deauth_dos_0, name, "Deauthentification Wifi Packets Injection").
cpv(wi_fi_deauth_dos, attack_vector, vector_wi_fi_deauth_dos_0).
attack_impact(impact_wi_fi_deauth_dos_0).
attack_impact(impact_wi_fi_deauth_dos_0, category, "Denial of control").
attack_impact(impact_wi_fi_deauth_dos_0, description, "The user can not stop the CPS").
cpv(wi_fi_deauth_dos, attack_vector, impact_wi_fi_deauth_dos_0).
cpv(wi_fi_deauth_dos, exploit_step(0), "Set the Wi-Fi card into monitor mode and find the BSSID and channel number for the CPS's Wi-Fi network.").
cpv(wi_fi_deauth_dos, exploit_step(1), "Send a deauthentication packet to the WIFI Interface.").
cpv(wi_fi_deauth_dos, reference_url, "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV001").
