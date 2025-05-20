cpv(projector_optical_flow).
cpv(projector_optical_flow, required_component, optical_flow_sensor).
cpv(projector_optical_flow, required_component, px4controller).
cpv(projector_optical_flow, required_component, esc).
cpv(projector_optical_flow, required_component, multi_copter_motor).
cpv(projector_optical_flow, entry_component, optical_flow_sensor).
cpv(projector_optical_flow, exit_component, multi_copter_motor).
cpv(projector_optical_flow, vulnerability, optical_flow_spoofing_vuln).
cpv(projector_optical_flow, vulnerability, px4controller_integrity_vuln).
cpv(projector_optical_flow, initial_condition("Position"), "Any").
cpv(projector_optical_flow, initial_condition("Heading"), "Any").
cpv(projector_optical_flow, initial_condition("Speed"), "None").
cpv(projector_optical_flow, initial_condition("Environment"), "Any").
cpv(projector_optical_flow, initial_condition("RemoteController"), "On").
cpv(projector_optical_flow, initial_condition("CPSController"), "None").
cpv(projector_optical_flow, initial_condition("Operating mode"), "Hold").
cpv(projector_optical_flow, attack_requirement, "Projector or Laser-based spoofing device").
attack_vector(vector_projector_optical_flow_0).
attack_vector(vector_projector_optical_flow_0, name, "Optical Flow Spoofing Signal Injection").
attack_signal(signal_projector_optical_flow_0).
attack_signal(signal_projector_optical_flow_0, src, external_input).
attack_signal(signal_projector_optical_flow_0, dst, optical_flow_sensor).
attack_signal(signal_projector_optical_flow_0, modality, image).
attack_vector(vector_projector_optical_flow_0, signal, signal_projector_optical_flow_0).
attack_vector(vector_projector_optical_flow_0, required_access_level, "Physical").
attack_vector(vector_projector_optical_flow_0, configuration("duration"), "Permanent").
attack_vector(vector_projector_optical_flow_0, name, "Optical Flow Spoofing Signal Injection").
cpv(projector_optical_flow, attack_vector, vector_projector_optical_flow_0).
attack_impact(impact_projector_optical_flow_0).
attack_impact(impact_projector_optical_flow_0, category, "Control Manipulation").
attack_impact(impact_projector_optical_flow_0, description, "CPS drifts uncontrollably or exhibits unintended lateral movement targeted by the attackers.").
cpv(projector_optical_flow, attack_vector, impact_projector_optical_flow_0).
cpv(projector_optical_flow, exploit_step(0), "Position the spoofing device in the UAV's optical flow sensor field.").
cpv(projector_optical_flow, exploit_step(1), "Project high-contrast patterns using a laser or projector.").
cpv(projector_optical_flow, exploit_step(2), "Move the projected pattern to mislead corner detection algorithms.").
cpv(projector_optical_flow, exploit_step(3), "Observe the drone drift following the displacement of the projected pattern.").
cpv(projector_optical_flow, reference_url, "https://www.usenix.org/system/files/conference/woot16/woot16-paper-davidson.pdf").
