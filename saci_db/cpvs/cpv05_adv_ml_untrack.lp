cpv(object_track).
cpv(object_track, required_component, camera).
cpv(object_track, required_component, dnn).
cpv(object_track, required_component, px4controller).
cpv(object_track, required_component, esc).
cpv(object_track, required_component, multi_copter_motor).
cpv(object_track, entry_component, camera).
cpv(object_track, exit_component, multi_copter_motor).
cpv(object_track, vulnerability, deep_neural_network_vuln).
cpv(object_track, initial_condition("Position"), "Any").
cpv(object_track, initial_condition("Heading"), "Any").
cpv(object_track, initial_condition("Speed"), "Any").
cpv(object_track, initial_condition("Environment"), "Any").
cpv(object_track, initial_condition("RemoteController"), "Any").
cpv(object_track, initial_condition("CPSController"), "Any").
cpv(object_track, initial_condition("Operating mode"), "Autonomous").
cpv(object_track, attack_requirement, "Adversarial patches generated use adversarial machine learning").
cpv(object_track, attack_requirement, "Decompiled DNN model from the firmware").
attack_vector(vector_object_track_0).
attack_vector(vector_object_track_0, name, "Adversarial Pattern Injection").
attack_signal(signal_object_track_0).
attack_signal(signal_object_track_0, src, external_input).
attack_signal(signal_object_track_0, dst, dnn).
attack_signal(signal_object_track_0, modality, image).
attack_vector(vector_object_track_0, signal, signal_object_track_0).
attack_vector(vector_object_track_0, required_access_level, "Remote").
attack_vector(vector_object_track_0, configuration("duration"), "Transient").
attack_vector(vector_object_track_0, name, "Adversarial Pattern Injection").
cpv(object_track, attack_vector, vector_object_track_0).
attack_impact(impact_object_track_0).
attack_impact(impact_object_track_0, category, "Control Manipulation").
attack_impact(impact_object_track_0, description, "The attacker can manipulate the autonomous CPS behavior by injecting adversarial patterns ").
cpv(object_track, attack_vector, impact_object_track_0).
cpv(object_track, exploit_step(0), "Decompile the DNN model from the CPS firmware.").
cpv(object_track, exploit_step(1), "Dump the source code and model weight of the DNN model").
cpv(object_track, exploit_step(2), "Generate adversarial examples using adversarial machine learning-based optimization.").
cpv(object_track, exploit_step(3), "Showcase the adversarial examples to the CPS camera for control manipulation.").
