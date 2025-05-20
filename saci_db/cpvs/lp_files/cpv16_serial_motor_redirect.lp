cpv(redirect).
cpv(redirect, required_component, serial).
cpv(redirect, required_component, controller).
cpv(redirect, required_component, controller).
cpv(redirect, required_component, esc).
cpv(redirect, required_component, motor).
cpv(redirect, entry_component, serial).
cpv(redirect, exit_component, motor).
cpv(redirect, vulnerability, lack_serial_authentication_vuln).
cpv(redirect, initial_condition("Position"), "Any").
cpv(redirect, initial_condition("Heading"), "Any").
cpv(redirect, initial_condition("Speed"), "Any").
cpv(redirect, initial_condition("Environment"), "Any").
cpv(redirect, initial_condition("RemoteController"), "On").
cpv(redirect, initial_condition("CPSController"), "Moving").
cpv(redirect, initial_condition("Operating mode"), "Any").
cpv(redirect, attack_requirement, "Computer").
cpv(redirect, attack_requirement, "USB-C cable").
attack_vector(vector_redirect_0).
attack_vector(vector_redirect_0, name, "Serial DSHOT_CMD_SPIN_DIRECTION_1 Command Injection").
attack_signal(signal_redirect_0).
attack_signal(signal_redirect_0, src, external_input).
attack_signal(signal_redirect_0, dst, serial).
attack_signal(signal_redirect_0, modality, serial_commands).
attack_signal(signal_redirect_0, data, "7").
attack_vector(vector_redirect_0, signal, signal_redirect_0).
attack_vector(vector_redirect_0, required_access_level, "Physical").
attack_vector(vector_redirect_0, configuration("repetition"), "6").
attack_vector(vector_redirect_0, name, "Serial DSHOT_CMD_SPIN_DIRECTION_1 Command Injection").
cpv(redirect, attack_vector, vector_redirect_0).
attack_vector(vector_redirect_1).
attack_vector(vector_redirect_1, name, "Serial DSHOT_CMD_SPIN_DIRECTION_2 Command Injection").
attack_signal(signal_redirect_1).
attack_signal(signal_redirect_1, src, external_input).
attack_signal(signal_redirect_1, dst, serial).
attack_signal(signal_redirect_1, modality, serial_commands).
attack_signal(signal_redirect_1, data, "8").
attack_vector(vector_redirect_1, signal, signal_redirect_1).
attack_vector(vector_redirect_1, required_access_level, "Physical").
attack_vector(vector_redirect_1, configuration("repetition"), "6").
attack_vector(vector_redirect_1, name, "Serial DSHOT_CMD_SPIN_DIRECTION_2 Command Injection").
cpv(redirect, attack_vector, vector_redirect_1).
attack_vector(vector_redirect_2).
attack_vector(vector_redirect_2, name, "Serial CMD_SAVE_SETTINGS Command Injection").
attack_signal(signal_redirect_2).
attack_signal(signal_redirect_2, src, external_input).
attack_signal(signal_redirect_2, dst, serial).
attack_signal(signal_redirect_2, modality, serial_commands).
attack_signal(signal_redirect_2, data, "12").
attack_vector(vector_redirect_2, signal, signal_redirect_2).
attack_vector(vector_redirect_2, required_access_level, "Physical").
attack_vector(vector_redirect_2, configuration("repetition"), "6").
attack_vector(vector_redirect_2, name, "Serial CMD_SAVE_SETTINGS Command Injection").
cpv(redirect, attack_vector, vector_redirect_2).
attack_impact(impact_redirect_0).
attack_impact(impact_redirect_0, category, "Manipulation of Control").
attack_impact(impact_redirect_0, description, "The CPS moves in opposite direction than expected").
cpv(redirect, attack_vector, impact_redirect_0).
cpv(redirect, exploit_step(0), "Open a terminal emulator and connect to the serial device exposed by the CPS device. You may need root access.").
cpv(redirect, exploit_step(1), "In the idle state, you should observe floating point outputs from the compass. If you do not, the retry the previous step.").
cpv(redirect, exploit_step(2), "Enter the number '7' six times into the terminal. This corresponds to the DSHOT_CMD_SPIN_DIRECTION_1 setting.").
cpv(redirect, exploit_step(3), "Use the web interface to command a drive signal. Observe the directions the wheel spin in. Navigate to http://192.168.4.1/Stop").
cpv(redirect, exploit_step(4), "Ensure the wheels stop spinning. If the wheel spun in the opposite direction as expected, skip to step 10.").
cpv(redirect, exploit_step(5), "Enter the number '8' six times into the terminal window. This corresponds to DSHOT_CMD_SPIN_DIRECTION_2.").
cpv(redirect, exploit_step(6), "Use the web interface to command a drive signal. Observe the directions the wheel spin in. Navigate to http://192.168.4.1/Stop").
cpv(redirect, exploit_step(7), "Ensure the wheels stop spinning. If the wheel spun in the same direction as expected, the CPS has not been configures to verify the CPV.").
cpv(redirect, exploit_step(8), "Enter the number '12' six times to save the DSHOT setings.Power down and restart the CPS Device. Use the web interface to command a drive signal.").
cpv(redirect, reference_url, "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV0011").
