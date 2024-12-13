cpv(web_move).
cpv(web_move, required_component, wifi).
cpv(web_move, required_component, web_server).
cpv(web_move, required_component, controller).
cpv(web_move, required_component, controller).
cpv(web_move, required_component, esc).
cpv(web_move, required_component, motor).
cpv(web_move, entry_component, wifi).
cpv(web_move, exit_component, motor).
cpv(web_move, vulnerability, wifi_known_creds_vuln).
cpv(web_move, vulnerability, weak_application_auth_vuln).
cpv(web_move, initial_condition("Position"), "Any").
cpv(web_move, initial_condition("Heading"), "Any").
cpv(web_move, initial_condition("Speed"), "Any").
cpv(web_move, initial_condition("Environment"), "Any").
cpv(web_move, initial_condition("RemoteController"), "On").
cpv(web_move, initial_condition("CPSController"), "Idle").
cpv(web_move, initial_condition("Operating mode"), "Manual").
cpv(web_move, attack_requirement, "Attacker computer").
cpv(web_move, attack_requirement, "Firmware for the Renesas RA4M1 processor on the Arduino Uno R4 to retrieve hard coded credentials.").
attack_vector(vector_web_move_0).
attack_vector(vector_web_move_0, name, "Move Button Manipulation via HTTP Requests Injection").
attack_signal(signal_web_move_0).
attack_signal(signal_web_move_0, src, external_input).
attack_signal(signal_web_move_0, dst, wifi).
attack_signal(signal_web_move_0, modality, network_packets).
attack_vector(vector_web_move_0, signal, signal_web_move_0).
attack_vector(vector_web_move_0, required_access_level, "Proximity").
attack_vector(vector_web_move_0, configuration("duration"), "permanent").
attack_vector(vector_web_move_0, name, "Move Button Manipulation via HTTP Requests Injection").
cpv(web_move, attack_vector, vector_web_move_0).
attack_impact(impact_web_move_0).
attack_impact(impact_web_move_0, category, "Manipulation of control.").
attack_impact(impact_web_move_0, description, "The CPS starts driving without the operator control").
cpv(web_move, attack_vector, impact_web_move_0).
cpv(web_move, exploit_step(0), "Connect to Wi-Fi network using the hardcoded credentials”").
cpv(web_move, exploit_step(1), "Using a web browser, navigate to webserver IP address").
cpv(web_move, exploit_step(2), "Observe that the cps remains idle").
cpv(web_move, exploit_step(3), "Click either of the drive buttons").
cpv(web_move, exploit_step(4), "Ensure the rover begins to drive").
cpv(web_move, reference_url, "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV009/HII-NGP1AROV1ARR03-CPV009-20240911.docx").
