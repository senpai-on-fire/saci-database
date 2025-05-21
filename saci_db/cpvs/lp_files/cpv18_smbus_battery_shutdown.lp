cpv(sm_bus_battery_shutdown).
cpv(sm_bus_battery_shutdown, required_component, sm_bus).
cpv(sm_bus_battery_shutdown, required_component, bms).
cpv(sm_bus_battery_shutdown, required_component, battery).
cpv(sm_bus_battery_shutdown, required_component, esc).
cpv(sm_bus_battery_shutdown, entry_component, sm_bus).
cpv(sm_bus_battery_shutdown, exit_component, esc).
cpv(sm_bus_battery_shutdown, vulnerability, lack_serial_authentication_vuln).
cpv(sm_bus_battery_shutdown, initial_condition("Position"), "Any").
cpv(sm_bus_battery_shutdown, initial_condition("Heading"), "Any").
cpv(sm_bus_battery_shutdown, initial_condition("Speed"), "Any").
cpv(sm_bus_battery_shutdown, initial_condition("Environment"), "Any").
cpv(sm_bus_battery_shutdown, initial_condition("Software state"), "Any").
cpv(sm_bus_battery_shutdown, initial_condition("Operator Supervision"), "Any").
cpv(sm_bus_battery_shutdown, attack_requirement, "BQStudio version 1.3.127").
cpv(sm_bus_battery_shutdown, attack_requirement, "TI EV2400 EVM Interface board").
attack_vector(vector_sm_bus_battery_shutdown_0).
attack_vector(vector_sm_bus_battery_shutdown_0, name, "SMBus Shutdown Command Injection").
attack_signal(signal_sm_bus_battery_shutdown_0).
attack_signal(signal_sm_bus_battery_shutdown_0, src, external_input).
attack_signal(signal_sm_bus_battery_shutdown_0, dst, sm_bus).
attack_signal(signal_sm_bus_battery_shutdown_0, modality, serial_commands).
attack_vector(vector_sm_bus_battery_shutdown_0, signal, signal_sm_bus_battery_shutdown_0).
attack_vector(vector_sm_bus_battery_shutdown_0, required_access_level, "Physical").
attack_vector(vector_sm_bus_battery_shutdown_0, name, "SMBus Shutdown Command Injection").
cpv(sm_bus_battery_shutdown, attack_vector, vector_sm_bus_battery_shutdown_0).
attack_impact(impact_sm_bus_battery_shutdown_0).
attack_impact(impact_sm_bus_battery_shutdown_0, category, "Loss of control").
attack_impact(impact_sm_bus_battery_shutdown_0, description, "system does not provide power to subsystem").
cpv(sm_bus_battery_shutdown, attack_vector, impact_sm_bus_battery_shutdown_0).
cpv(sm_bus_battery_shutdown, exploit_step(0), "Connect an SMBus cable between the SMBus connector on the EV2400 and J3 on the battery monitor board").
cpv(sm_bus_battery_shutdown, exploit_step(1), "Power system on using only battery power").
cpv(sm_bus_battery_shutdown, exploit_step(2), "Observe the system is operational, LEDs on the ESC are on").
cpv(sm_bus_battery_shutdown, exploit_step(3), "Open BQStudio").
cpv(sm_bus_battery_shutdown, exploit_step(4), "If the BQ40Z80 isn't detected automatically BQStudio will prompt the user to select a device").
cpv(sm_bus_battery_shutdown, exploit_step(5), "Once connected through BQStudio, observe that the BQ40Z80 status is displayed on the screen").
cpv(sm_bus_battery_shutdown, exploit_step(6), "In the commands window click SHUTDOWN twice").
cpv(sm_bus_battery_shutdown, exploit_step(7), "The BQ40Z80 will enter shutdown mode disconnecting the power from the system").
cpv(sm_bus_battery_shutdown, exploit_step(8), "Observe the ESC board LEDs are disabled.").
cpv(sm_bus_battery_shutdown, reference_url, "https://github.com/senpai-on-fire/Greensight1A-esc-CPVs/blob/main/CPV001/HII-GSP1AESC01NR017-CPV001-20240926.docx").
