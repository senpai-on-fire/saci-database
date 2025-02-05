cpv(esc_bootloader).
cpv(esc_bootloader, required_component, debug).
cpv(esc_bootloader, required_component, esc).
cpv(esc_bootloader, required_component, motor).
cpv(esc_bootloader, entry_component, debug).
cpv(esc_bootloader, exit_component, motor).
cpv(esc_bootloader, vulnerability, lack_serial_authentication_vuln).
cpv(esc_bootloader, initial_condition("Position"), "Any").
cpv(esc_bootloader, initial_condition("Heading"), "Any").
cpv(esc_bootloader, initial_condition("Speed"), "Any").
cpv(esc_bootloader, initial_condition("Environment"), "Any").
cpv(esc_bootloader, initial_condition("Software state"), "On").
cpv(esc_bootloader, initial_condition("Operator Supervision"), "Any").
cpv(esc_bootloader, attack_requirement, "physical access").
cpv(esc_bootloader, attack_requirement, "Debugging/programming hardware").
cpv(esc_bootloader, attack_requirement, "Software tools for accessing and programming STM32 microprocessors.").
cpv(esc_bootloader, attack_requirement, "Knowledge of STM32 boot-loader mode").
cpv(esc_bootloader, attack_requirement, "knowledge of programming protocols.").
attack_vector(vector_esc_bootloader_0).
attack_vector(vector_esc_bootloader_0, name, "Debug Commands Injection").
attack_signal(signal_esc_bootloader_0).
attack_signal(signal_esc_bootloader_0, src, external_input).
attack_signal(signal_esc_bootloader_0, dst, debug).
attack_signal(signal_esc_bootloader_0, modality, serial_commands).
attack_vector(vector_esc_bootloader_0, signal, signal_esc_bootloader_0).
attack_vector(vector_esc_bootloader_0, required_access_level, "Physical").
attack_vector(vector_esc_bootloader_0, name, "Debug Commands Injection").
cpv(esc_bootloader, attack_vector, vector_esc_bootloader_0).
attack_impact(impact_esc_bootloader_0).
attack_impact(impact_esc_bootloader_0, category, "Loss of control").
attack_impact(impact_esc_bootloader_0, description, "ESC will not start motor").
cpv(esc_bootloader, attack_vector, impact_esc_bootloader_0).
cpv(esc_bootloader, exploit_step(0), "Connect to the ESC via a USB-TTL serial adapter using a terminal emulator with a baud rate of 38400.").
cpv(esc_bootloader, exploit_step(1), "Arm the ESC and start the motor.").
cpv(esc_bootloader, exploit_step(2), "Use the microprocessor programmer to connect to the STM32.").
cpv(esc_bootloader, exploit_step(3), "Follow the procedure to write the HII-GSP1AESC01NR017-CPV003_FF.hex file to the STM32.").
cpv(esc_bootloader, exploit_step(4), "Use the microprocessor programmer to reset the STM32.").
cpv(esc_bootloader, exploit_step(5), "Reconnect to the USB-TTL serial adapter using the terminal emulator.").
cpv(esc_bootloader, exploit_step(6), "The terminal emulator will likely not connect and the motor does not begin to spin.").
cpv(esc_bootloader, reference_url, "https://github.com/senpai-on-fire/Greensight1A-esc-CPVs/blob/main/CPV003/HII-GSP1AESC01NR017-CPV003-20241002.docx").
