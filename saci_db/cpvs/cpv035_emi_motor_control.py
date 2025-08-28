
from saci.modeling import CPV
from saci.modeling.state import GlobalState

from saci_db.vulns.pwm_spoofing_vuln import PWMSpoofingVuln
from saci_db.vulns.lack_emi_pwm_shielding_vuln import LackEMIPWMShieldingPred

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.magnetic_attack_signal import MagneticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput

from saci.modeling.device import ESC, PWMChannel, Motor


class EMIMotorFullControlCPV(CPV):
    NAME = "The Full Control on PWM Signals to Motors using EMI"

    def __init__(self):
        super().__init__(
            
            required_components=[
                PWMChannel(), # This is the entry component (Required)
                ESC(), # This is a vulnerable required component (Required)
                Motor() # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            
            entry_component=PWMChannel(),
            exit_component=Motor(),
            
            vulnerabilities=[PWMSpoofingVuln(), LackEMIPWMShieldingPred()],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Moving",
                "Operating mode": "Mission",
            },
            
            attack_requirements=[
                "RF Signal Generator",
                "Power Amplifier",
                "Directional Antenna",
                "Spectrum Analyzer",
            ],
            
            attack_vectors=[
                BaseAttackVector(
                    name="Electromagnetic Signals Interference",
                    signal=MagneticAttackSignal(src=ExternalInput(), dst=PWMChannel()),
                    required_access_level="Remote",
                    configuration={"duration": "permanent"},
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Attacker can set motor RPM to arbitrary value that the attacker chooses",
                )
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Create a model to analyze the impact of the Full Control Waveform Attack on PWM-controlled actuators.",
                    "The model must include:",
                    "    - Controller logic algorithm governing actuator behavior.",
                    "    - PWM signal generation and motor control system.",
                    "    - Electromagnetic interference (EMI) injection model using carefully modulated waveforms to fully override PWM signals.",
                    "    - Actuator response to fully controlled EMI-based PWM signal manipulation.",
                    "    - Environmental influences on EMI propagation and interference effectiveness.",
                    "Identify key attack parameters for achieving full actuator control:",
                    "    - The legitimate PWM signal characteristics, including frequency, duty cycle, and amplitude.",
                    "    - The resonant frequency of the PWM circuitry to maximize interference.",
                    "    - The waveform parameters (frequency, amplitude, and modulation) required to override the legitimate PWM signal and inject new actuator control commands.",
                    "Simulate the effects of a controlled waveform injection to override legitimate PWM signals:",
                    "    - Observe system behavior under different interference parameters.",
                    "    - Determine the conditions under which the attacker achieves complete control over the actuator.",
                "TA2 Exploit Steps",
                    "Implement the simulation model using advanced electromagnetic and control system analysis tools.",
                    "Configure the simulation environment with realistic actuator parameters and PWM control characteristics.",
                    "Simulate the attack by injecting a fully controlled modulated waveform designed to replace the legitimate PWM signal.",
                    "Monitor system response metrics, including:",
                    "    - Actuator movement under attacker-defined control signals.",
                    "    - Complete override of the original PWM command set.",
                    "    - Latency and stability of the attack under dynamic motor conditions.",
                    "Perform parametric analysis:",
                    "    - Adjust waveform frequency and amplitude to determine optimal attack conditions.",
                    "    - Evaluate the effectiveness of different modulation schemes for precise control over motor direction, speed, and position.",
                    "    - Identify how variations in attack distance, power levels, and environmental noise affect control reliability.",
                    "Compare results against baseline operation to quantify the extent of attacker control over the actuator.",
                    "Validate findings by cross-referencing with theoretical models and previous research on EMI-induced control hijacking.",
                "TA3 Exploit Steps",
                    "Prepare the experimental setup to test the Full Control Waveform Attack on a physical PWM-controlled actuator.",
                    "Gather the necessary equipment:",
                    "    - Signal generator capable of producing fully modulated control waveforms.",
                    "    - Amplifier to enhance the interference signal strength.",
                    "    - Antenna optimized for coupling EMI into the PWM circuitry.",
                    "    - Measurement tools such as oscilloscopes and spectrum analyzers.",
                    "Identify the PWM signal characteristics:",
                    "    - Measure the nominal frequency, duty cycle, and amplitude of the PWM control signal.",
                    "    - Conduct spectrum analysis to determine the actuator’s susceptibility to external EMI-based waveform control.",
                    "Position the interference antenna close to the PWM transmission medium (e.g., motor control wires or PCB traces).",
                    "Emit a fully controlled modulated waveform designed to replace the legitimate PWM signal.",
                    "Gradually increase the signal power while monitoring actuator response:",
                    "    - Observe whether the actuator follows the attacker's injected commands.",
                    "    - Detect any degradation in response consistency or stability.",
                    "    - Measure deviations in expected PWM output waveforms using an oscilloscope.",
                    "Optimize attack parameters:",
                    "    - Adjust signal modulation and amplitude to sustain complete actuator control.",
                    "    - Identify the minimum power threshold required to fully override the PWM signal.",
                    "    - Experiment with different control inputs to verify the attack's precision and repeatability.",
            ],
            
            associated_files=[],
            reference_urls=["https://www.usenix.org/system/files/sec22-dayanikli.pdf"],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
