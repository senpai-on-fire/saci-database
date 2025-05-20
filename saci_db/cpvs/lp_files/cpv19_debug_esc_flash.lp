cpv(esc_flash).
cpv(esc_flash, required_component, debug).
cpv(esc_flash, required_component, esc).
cpv(esc_flash, required_component, motor).
cpv(esc_flash, entry_component, debug).
cpv(esc_flash, exit_component, motor).
cpv(esc_flash, vulnerability, lack_serial_authentication_vuln).
cpv(esc_flash, initial_condition("Position"), "Any").
cpv(esc_flash, initial_condition("Heading"), "Any").
cpv(esc_flash, initial_condition("Speed"), "Any").
cpv(esc_flash, initial_condition("Environment"), "Any").
cpv(esc_flash, initial_condition("Software state"), "On").
cpv(esc_flash, initial_condition("Operator Supervision"), "Any").
cpv(esc_flash, attack_requirement, "USB-TTL Serial Adapter").
cpv(esc_flash, attack_requirement, "Terminal Emulator Software").
cpv(esc_flash, attack_requirement, "script used to attack").
attack_vector(vector_esc_flash_0).
attack_vector(vector_esc_flash_0, name, "Debug Commands Injection").
attack_signal(signal_esc_flash_0).
attack_signal(signal_esc_flash_0, src, external_input).
attack_signal(signal_esc_flash_0, dst, debug).
attack_signal(signal_esc_flash_0, modality, serial_commands).
attack_signal(signal_esc_flash_0, data, "specific sequence of bytes").
attack_vector(vector_esc_flash_0, signal, signal_esc_flash_0).
attack_vector(vector_esc_flash_0, required_access_level, "Physical").
attack_vector(vector_esc_flash_0, name, "Debug Commands Injection").
cpv(esc_flash, attack_vector, vector_esc_flash_0).
attack_impact(impact_esc_flash_0).
attack_impact(impact_esc_flash_0, category, "Denial of control").
attack_impact(impact_esc_flash_0, description, "Motor stops spinning").
cpv(esc_flash, attack_vector, impact_esc_flash_0).
cpv(esc_flash, exploit_step(0), "Send a throttle command of zero to initialize the motor/firmware state.").
cpv(esc_flash, exploit_step(1), "Send a throttle command to engage the motor.").
cpv(esc_flash, exploit_step(2), "Observe that the motor begins to spin.").
cpv(esc_flash, exploit_step(3), "Send the data following data to enter bootloader mode.").
cpv(esc_flash, exploit_step(4), "Observe that the motor stops spinning.").
cpv(esc_flash, reference_url, "https://github.com/senpai-on-fire/Greensight1A-esc-CPVs/blob/main/CPV002/HII-GSP1AESC01NR017-CPV002-20240930.docx").
