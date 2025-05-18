cpv(web_crash).
cpv(web_crash, required_component, wifi).
cpv(web_crash, required_component, web_server).
cpv(web_crash, required_component, controller).
cpv(web_crash, required_component, controller).
cpv(web_crash, required_component, esc).
cpv(web_crash, required_component, motor).
cpv(web_crash, entry_component, wifi).
cpv(web_crash, exit_component, motor).
cpv(web_crash, vulnerability, wifi_known_creds_vuln).
cpv(web_crash, vulnerability, weak_application_auth_vuln).
cpv(web_crash, initial_condition("Position"), "Any").
cpv(web_crash, initial_condition("Heading"), "Any").
cpv(web_crash, initial_condition("Speed"), "Any").
cpv(web_crash, initial_condition("Environment"), "Any").
cpv(web_crash, initial_condition("RemoteController"), "On").
cpv(web_crash, initial_condition("CPSController"), "Moving").
cpv(web_crash, initial_condition("Operating mode"), "Manual").
cpv(web_crash, attack_requirement, "Computer").
cpv(web_crash, attack_requirement, "Hardcoded credentials").
attack_vector(vector_web_crash_0).
attack_vector(vector_web_crash_0, name, "Long HTTP GET Requests Injection").
attack_signal(signal_web_crash_0).
attack_signal(signal_web_crash_0, src, external_input).
attack_signal(signal_web_crash_0, dst, wifi).
attack_signal(signal_web_crash_0, modality, network_packets).
attack_vector(vector_web_crash_0, signal, signal_web_crash_0).
attack_vector(vector_web_crash_0, required_access_level, "Proximity").
attack_vector(vector_web_crash_0, configuration("duration"), "permanent").
attack_vector(vector_web_crash_0, name, "Long HTTP GET Requests Injection").
cpv(web_crash, attack_vector, vector_web_crash_0).
attack_impact(impact_web_crash_0).
attack_impact(impact_web_crash_0, category, "Loss of control").
attack_impact(impact_web_crash_0, description, "The user can not stop the CPS while driving").
cpv(web_crash, attack_vector, impact_web_crash_0).
cpv(web_crash, exploit_step(0), "Connect to rover Wi-Fi using hardcoded credentials").
cpv(web_crash, exploit_step(1), "Issue a long HTTP GET request (at least 26,000 characters) to the webserver address").
cpv(web_crash, reference_url, "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV003/HII-NGP1AROV1ARR03-CPV003-20240828.docx").
