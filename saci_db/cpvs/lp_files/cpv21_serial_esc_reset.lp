cpv(esc_reset).
cpv(esc_reset, required_component, serial).
cpv(esc_reset, required_component, esc).
cpv(esc_reset, entry_component, serial).
cpv(esc_reset, exit_component, esc).
cpv(esc_reset, vulnerability, lack_serial_authentication_vuln).
cpv(esc_reset, initial_condition("Position"), "Any").
cpv(esc_reset, initial_condition("Heading"), "Any").
cpv(esc_reset, initial_condition("Speed"), "Any").
cpv(esc_reset, initial_condition("Environment"), "Any").
cpv(esc_reset, initial_condition("Software state"), "On").
cpv(esc_reset, initial_condition("Operator Supervision"), "Any").
cpv(esc_reset, attack_requirement, "physical access").
cpv(esc_reset, attack_requirement, "Microprocessor Programmer").
cpv(esc_reset, attack_requirement, "1-Wire Serial Interface Adapter").
cpv(esc_reset, attack_requirement, "Terminal Emulator Software").
attack_vector(vector_esc_reset_0).
attack_vector(vector_esc_reset_0, name, "Serial Reset Command Injection").
attack_signal(signal_esc_reset_0).
attack_signal(signal_esc_reset_0, src, external_input).
attack_signal(signal_esc_reset_0, dst, serial).
attack_signal(signal_esc_reset_0, modality, serial_commands).
attack_vector(vector_esc_reset_0, signal, signal_esc_reset_0).
attack_vector(vector_esc_reset_0, required_access_level, "Physical").
attack_vector(vector_esc_reset_0, name, "Serial Reset Command Injection").
cpv(esc_reset, attack_vector, vector_esc_reset_0).
attack_impact(impact_esc_reset_0).
attack_impact(impact_esc_reset_0, category, "Loss of availability").
attack_impact(impact_esc_reset_0, description, "ESC will repeatedly reset every 3s").
cpv(esc_reset, attack_vector, impact_esc_reset_0).
cpv(esc_reset, exploit_step(0), "Send a throttle command of zero to initialize the motor/firmware state.").
cpv(esc_reset, exploit_step(1), "Send a throttle command to engage the motor and observe that the motor begins to spin.").
cpv(esc_reset, exploit_step(2), "Send a throttle command of zero to stop the motor.").
cpv(esc_reset, exploit_step(3), "Reset power to ESC. In theory this should not be necessary, but in practice values could not be set reliably if a non-zero throttle had been commanded within the same power cycle.").
cpv(esc_reset, exploit_step(4), "Send the data following data to set the prot_volt configuration value:").
cpv(esc_reset, exploit_step(5), "Send the data following data to set the prot_cells configuration value:").
cpv(esc_reset, exploit_step(6), "Save the configuration changes").
cpv(esc_reset, exploit_step(7), "Repeat steps 1 & 2 to engage the motor.").
cpv(esc_reset, exploit_step(8), "Observe that the motor either begins to spin and stops within three seconds or will not start at all").
cpv(esc_reset, reference_url, "https://github.com/senpai-on-fire/Greensight1A-esc-CPVs/blob/main/CPV004/HII-GSP1AESC01NR017-CPV004-20241003.docx").
