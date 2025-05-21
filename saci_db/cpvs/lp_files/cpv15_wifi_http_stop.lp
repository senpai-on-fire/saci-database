cpv(web_stop).
cpv(web_stop, required_component, wifi).
cpv(web_stop, required_component, web_server).
cpv(web_stop, required_component, controller).
cpv(web_stop, required_component, controller).
cpv(web_stop, required_component, esc).
cpv(web_stop, required_component, motor).
cpv(web_stop, entry_component, wifi).
cpv(web_stop, exit_component, motor).
cpv(web_stop, vulnerability, wifi_known_creds_vuln).
cpv(web_stop, vulnerability, weak_application_auth_vuln).
cpv(web_stop, initial_condition("Position"), "Any").
cpv(web_stop, initial_condition("Heading"), "Any").
cpv(web_stop, initial_condition("Speed"), "Any").
cpv(web_stop, initial_condition("Environment"), "Any").
cpv(web_stop, initial_condition("RemoteController"), "On").
cpv(web_stop, initial_condition("CPSController"), "driving").
cpv(web_stop, initial_condition("Operating mode"), "Mission").
cpv(web_stop, attack_requirement, "Computer").
cpv(web_stop, attack_requirement, "Hardcoded credentials").
attack_vector(vector_web_stop_0).
attack_vector(vector_web_stop_0, name, "Stop Button Manipulation via HTTP Requests Injection").
attack_signal(signal_web_stop_0).
attack_signal(signal_web_stop_0, src, external_input).
attack_signal(signal_web_stop_0, dst, wifi).
attack_signal(signal_web_stop_0, modality, network_packets).
attack_vector(vector_web_stop_0, signal, signal_web_stop_0).
attack_vector(vector_web_stop_0, required_access_level, "Proximity").
attack_vector(vector_web_stop_0, configuration("duration"), "permanent").
attack_vector(vector_web_stop_0, name, "Stop Button Manipulation via HTTP Requests Injection").
cpv(web_stop, attack_vector, vector_web_stop_0).
attack_impact(impact_web_stop_0).
attack_impact(impact_web_stop_0, category, "Manipulation of control.").
attack_impact(impact_web_stop_0, description, "The CPS stop without the operator input").
cpv(web_stop, attack_vector, impact_web_stop_0).
cpv(web_stop, exploit_step(0), "Connect to Wi-Fi network using the hardcoded credentials").
cpv(web_stop, exploit_step(1), "Using a web browser, navigate to the webserver IP address").
cpv(web_stop, exploit_step(2), "Observe that the CPS remains idle").
cpv(web_stop, exploit_step(3), "Click either of the drive buttons").
cpv(web_stop, exploit_step(4), "Ensure the rover begins to drive").
cpv(web_stop, reference_url, "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV009/HII-NGP1AROV1ARR03-CPV009-20240911.docx").
