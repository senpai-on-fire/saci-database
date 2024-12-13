cpv(depth_camera_do_s).
cpv(depth_camera_do_s, required_component, depth_camera).
cpv(depth_camera_do_s, required_component, px4controller).
cpv(depth_camera_do_s, required_component, esc).
cpv(depth_camera_do_s, required_component, multi_copter_motor).
cpv(depth_camera_do_s, entry_component, depth_camera).
cpv(depth_camera_do_s, exit_component, multi_copter_motor).
cpv(depth_camera_do_s, vulnerability, depth_camera_spoofing_vuln).
cpv(depth_camera_do_s, initial_condition("Position"), "Any").
cpv(depth_camera_do_s, initial_condition("Heading"), "Any").
cpv(depth_camera_do_s, initial_condition("Speed"), "Any").
cpv(depth_camera_do_s, initial_condition("Environment"), "Any").
cpv(depth_camera_do_s, initial_condition("RemoteController"), "Any").
cpv(depth_camera_do_s, initial_condition("CPSController"), "Any").
cpv(depth_camera_do_s, initial_condition("Operating mode"), "Any").
cpv(depth_camera_do_s, attack_requirement, "Laser projector or high-lumen flashlight").
attack_vector(vector_depth_camera_do_s_0).
attack_vector(vector_depth_camera_do_s_0, name, "Laser Projection Interference").
attack_signal(signal_depth_camera_do_s_0).
attack_signal(signal_depth_camera_do_s_0, src, external_input).
attack_signal(signal_depth_camera_do_s_0, dst, depth_camera).
attack_signal(signal_depth_camera_do_s_0, modality, laser light).
attack_vector(vector_depth_camera_do_s_0, signal, signal_depth_camera_do_s_0).
attack_vector(vector_depth_camera_do_s_0, required_access_level, "Physical").
attack_vector(vector_depth_camera_do_s_0, configuration("pattern"), "beam").
attack_vector(vector_depth_camera_do_s_0, configuration("duration"), "permanent").
attack_vector(vector_depth_camera_do_s_0, name, "Laser Projection Interference").
cpv(depth_camera_do_s, attack_vector, vector_depth_camera_do_s_0).
attack_impact(impact_depth_camera_do_s_0).
attack_impact(impact_depth_camera_do_s_0, category, "Control Manipulation").
attack_impact(impact_depth_camera_do_s_0, description, "The attacker can take control of the drone by making the drone believe there is obstacle ahead.").
cpv(depth_camera_do_s, attack_vector, impact_depth_camera_do_s_0).
cpv(depth_camera_do_s, exploit_step(0), "Aim two laser projector at the depth camera lens.").
cpv(depth_camera_do_s, exploit_step(1), "Project high-intensity light beams in a defined pattern to interfere with depth estimation.").
cpv(depth_camera_do_s, exploit_step(2), "Monitor and adjust the pattern to maintain a continuous disruption.Observe the false collision avoidance of the autonomous drone.").
cpv(depth_camera_do_s, reference_url, "https://www.usenix.org/system/files/sec22-zhou-ce.pdf").
