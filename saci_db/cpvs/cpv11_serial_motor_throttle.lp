cpv(throttle).
cpv(throttle, required_component, serial).
cpv(throttle, required_component, controller).
cpv(throttle, required_component, controller).
cpv(throttle, required_component, esc).
cpv(throttle, required_component, motor).
cpv(throttle, entry_component, serial).
cpv(throttle, exit_component, motor).
cpv(throttle, vulnerability, lack_serial_authentication_vuln).
cpv(throttle, initial_condition("Position"), "Any").
cpv(throttle, initial_condition("Heading"), "Any").
cpv(throttle, initial_condition("Speed"), "Any").
cpv(throttle, initial_condition("Environment"), "Any").
cpv(throttle, initial_condition("RemoteController"), "On").
cpv(throttle, initial_condition("CPSController"), "Moving").
cpv(throttle, initial_condition("Operating mode"), "Any").
cpv(throttle, attack_requirement, "Computer").
cpv(throttle, attack_requirement, "USB-C cable").
attack_vector(vector_throttle_0).
attack_vector(vector_throttle_0, name, "Serial DSHOT Command Injection").
attack_signal(signal_throttle_0).
attack_signal(signal_throttle_0, src, external_input).
attack_signal(signal_throttle_0, dst, serial).
attack_signal(signal_throttle_0, modality, serial_commands).
attack_signal(signal_throttle_0, data, "any").
attack_vector(vector_throttle_0, signal, signal_throttle_0).
attack_vector(vector_throttle_0, required_access_level, "Physical").
attack_vector(vector_throttle_0, name, "Serial DSHOT Command Injection").
cpv(throttle, attack_vector, vector_throttle_0).
attack_impact(impact_throttle_0).
attack_impact(impact_throttle_0, category, "Manipulation of Control").
attack_impact(impact_throttle_0, description, "The serial commands cause CPS device to start moving/driving").
cpv(throttle, attack_vector, impact_throttle_0).
cpv(throttle, exploit_step(0), "Open a terminal emulator and connect to the serial device exposed by the CPS device. You may need root access.").
cpv(throttle, exploit_step(1), "When the CPS is Idle, enter any number between 48-2047 (except 55, 66, & 77) into the terminal").
cpv(throttle, reference_url, "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV0011").
