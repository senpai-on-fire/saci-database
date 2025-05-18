cpv(roll_over).
cpv(roll_over, required_component, serial).
cpv(roll_over, required_component, controller).
cpv(roll_over, required_component, controller).
cpv(roll_over, required_component, esc).
cpv(roll_over, required_component, motor).
cpv(roll_over, entry_component, serial).
cpv(roll_over, exit_component, motor).
cpv(roll_over, vulnerability, lack_serial_authentication_vuln).
cpv(roll_over, initial_condition("Position"), "Any").
cpv(roll_over, initial_condition("Heading"), "Any").
cpv(roll_over, initial_condition("Speed"), "Any").
cpv(roll_over, initial_condition("Environment"), "Any").
cpv(roll_over, initial_condition("RemoteController"), "On").
cpv(roll_over, initial_condition("CPSController"), "Moving").
cpv(roll_over, initial_condition("Operating mode"), "Any").
cpv(roll_over, attack_requirement, "Computer").
cpv(roll_over, attack_requirement, "USB-C cable").
attack_vector(vector_roll_over_0).
attack_vector(vector_roll_over_0, name, "Serial DSHOT_3D_MODE_ON Commands Injection").
attack_signal(signal_roll_over_0).
attack_signal(signal_roll_over_0, src, external_input).
attack_signal(signal_roll_over_0, dst, serial).
attack_signal(signal_roll_over_0, modality, serial_commands).
attack_signal(signal_roll_over_0, data, "10").
attack_vector(vector_roll_over_0, signal, signal_roll_over_0).
attack_vector(vector_roll_over_0, required_access_level, "Physical").
attack_vector(vector_roll_over_0, configuration("repetition"), "6").
attack_vector(vector_roll_over_0, name, "Serial DSHOT_3D_MODE_ON Commands Injection").
cpv(roll_over, attack_vector, vector_roll_over_0).
attack_vector(vector_roll_over_1).
attack_vector(vector_roll_over_1, name, "Serial DSHOT_CMD_SAVE_SETTINGS Commands Injection").
attack_signal(signal_roll_over_1).
attack_signal(signal_roll_over_1, src, external_input).
attack_signal(signal_roll_over_1, dst, serial).
attack_signal(signal_roll_over_1, modality, serial_commands).
attack_signal(signal_roll_over_1, data, "12").
attack_vector(vector_roll_over_1, signal, signal_roll_over_1).
attack_vector(vector_roll_over_1, required_access_level, "Physical").
attack_vector(vector_roll_over_1, configuration("repetition"), "6").
attack_vector(vector_roll_over_1, configuration("repetition_window"), "35").
attack_vector(vector_roll_over_1, name, "Serial DSHOT_CMD_SAVE_SETTINGS Commands Injection").
cpv(roll_over, attack_vector, vector_roll_over_1).
attack_impact(impact_roll_over_0).
attack_impact(impact_roll_over_0, category, "Loss of Safety").
attack_impact(impact_roll_over_0, description, "The CPS device will move excessively fast").
cpv(roll_over, attack_vector, impact_roll_over_0).
attack_impact(impact_roll_over_1).
attack_impact(impact_roll_over_1, category, "Damage to Property").
attack_impact(impact_roll_over_1, description, "The CPS device will rollover").
cpv(roll_over, attack_vector, impact_roll_over_1).
cpv(roll_over, exploit_step(0), "Open a terminal emulator and connect to the serial device exposed by the CPS device. You may need root access.").
cpv(roll_over, exploit_step(1), "In the idle state, you should observe floating point outputs from the compass. If you do not, the retry the previous step.").
cpv(roll_over, exploit_step(2), "With the CPS device in idle state, enter the number 10 six times into the terminal. This corresponds to DSHOT_3D_MODE_ON.").
cpv(roll_over, exploit_step(3), "With the rover in idle state, enter the number 12 six times. This corresponds to the DSHOT_CMD_SAVE_SETTINGS.").
cpv(roll_over, exploit_step(4), "Restart the CPS device and control from the web interface.").
cpv(roll_over, reference_url, "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV006").
