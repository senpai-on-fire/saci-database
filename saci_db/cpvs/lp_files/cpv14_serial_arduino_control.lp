cpv(serial_arduino_control).
cpv(serial_arduino_control, required_component, serial).
cpv(serial_arduino_control, required_component, controller).
cpv(serial_arduino_control, required_component, controller).
cpv(serial_arduino_control, required_component, esc).
cpv(serial_arduino_control, required_component, motor).
cpv(serial_arduino_control, entry_component, serial).
cpv(serial_arduino_control, exit_component, motor).
cpv(serial_arduino_control, vulnerability, type).
cpv(serial_arduino_control, initial_condition("Position"), "Any").
cpv(serial_arduino_control, initial_condition("Heading"), "Any").
cpv(serial_arduino_control, initial_condition("Speed"), "Any").
cpv(serial_arduino_control, initial_condition("Environment"), "Any").
cpv(serial_arduino_control, initial_condition("RemoteController"), "On").
cpv(serial_arduino_control, initial_condition("CPSController"), "Moving, Idle").
cpv(serial_arduino_control, initial_condition("Operating mode"), "Any").
cpv(serial_arduino_control, attack_requirement, "Computer").
cpv(serial_arduino_control, attack_requirement, "USB-C cable").
attack_vector(vector_serial_arduino_control_0).
attack_vector(vector_serial_arduino_control_0, name, "Serial Arduino Commands Injection").
attack_signal(signal_serial_arduino_control_0).
attack_signal(signal_serial_arduino_control_0, src, external_input).
attack_signal(signal_serial_arduino_control_0, dst, serial).
attack_signal(signal_serial_arduino_control_0, modality, gps).
attack_vector(vector_serial_arduino_control_0, signal, signal_serial_arduino_control_0).
attack_vector(vector_serial_arduino_control_0, required_access_level, "Physical").
attack_vector(vector_serial_arduino_control_0, configuration("duration"), "one-time").
attack_vector(vector_serial_arduino_control_0, name, "Serial Arduino Commands Injection").
cpv(serial_arduino_control, attack_vector, vector_serial_arduino_control_0).
attack_impact(impact_serial_arduino_control_0).
attack_impact(impact_serial_arduino_control_0, category, "Control Manipulation").
attack_impact(impact_serial_arduino_control_0, description, "The CPS’s behavior can be altered in unintended ways, such as stopping mid-sequence, moving intermittently, or executing a sequence not commanded by the operator").
cpv(serial_arduino_control, attack_vector, impact_serial_arduino_control_0).
cpv(serial_arduino_control, exploit_step(0), "Configure the HackRF device and replace the GPS antenna.").
cpv(serial_arduino_control, exploit_step(1), "3. Transmit the spoofed GPS signal using specific commands.").
cpv(serial_arduino_control, exploit_step(2), "4. Connect the Arduino Uno R4 to a computer via USB.").
cpv(serial_arduino_control, exploit_step(3), "5. Open a terminal emulator or use provided scripts to send commands.").
cpv(serial_arduino_control, exploit_step(4), "6. Input specific commands:").
cpv(serial_arduino_control, exploit_step(5), "    - 77: Initiates a pre-programmed driving sequence.").
cpv(serial_arduino_control, exploit_step(6), "    - 66: Interrupts the sequence, stopping the rover.").
cpv(serial_arduino_control, exploit_step(7), "    - 55: Causes intermittent movements with brief motor engagements.").
cpv(serial_arduino_control, exploit_step(8), "7. Observe the corresponding effects on the CPS.").
cpv(serial_arduino_control, reference_url, "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV014").
