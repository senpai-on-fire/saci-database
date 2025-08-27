from typing import List, Type

from saci.modeling import CPV
from saci.modeling.state import GlobalState

from saci_db.vulns.pwm_spoofing_vuln import PWMSpoofingVuln
from saci_db.vulns.lack_emi_pwm_shielding_vuln import LackEMIPWMShieldingPred

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.magnetic_attack_signal import MagneticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput

from saci_db.devices.px4_quadcopter_device import PX4Controller
from saci.modeling.device import ESC, PWMChannel, MultiCopterMotor, Motor


class EMIMotorBlockRotateCPV(CPV):
    NAME = "The Block and Rotate on PWM Signals to Motors using EMI"

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
                "RF Signal Generators",
                "Amplifiers",
                "Near-Field Probes",
                "Loop Antennas or Coils ",
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
                    category="Manipulation of Control",
                    description="Attacker can set the RPM of the motors to 0, or flip its sign (make the motors go in reverse direction at the same speed)",
                )
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Develop a model to analyze the impact of the Block & Rotate Waveform Attack on PWM-controlled actuators.",
                    "The model must include:",
                    "    - Controller logic algorithm governing actuator behavior.",
                    "    - PWM signal generation and its role in motor control.",
                    "    - Electromagnetic interference (EMI) injection model using amplitude-modulated (AM) CW signals.",
                    "    - Actuator response to injected AM interference and disrupted PWM signals.",
                    "    - Environmental influences on EMI propagation and interference effectiveness.",
                    "Identify key attack parameters influencing the actuator’s response:",
                    "    - The nominal PWM signal characteristics, including frequency and amplitude.",
                    "    - The resonant frequency of the PWM circuitry to enhance the effectiveness of the attack.",
                    "    - The AM signal characteristics (modulation depth, carrier frequency, and modulation rate) that enable actuator manipulation.",
                    "Simulate the effects of an AM CW signal interfering with the legitimate PWM control signal:",
                    "    - Observe system behavior under different modulation depths and frequencies.",
                    "    - Determine the threshold at which the actuator exhibits blocked or unintended motion.",
                    "    - Identify potential mitigation strategies such as PWM signal filtering or shielding.",
                "TA2 Exploit Steps",
                    "Implement the simulation model using electromagnetic and control system analysis tools.",
                    "Configure the simulation environment with realistic actuator parameters and PWM characteristics.",
                    "Simulate the attack by injecting an AM CW signal at the resonant frequency of the PWM circuitry, with modulation intended to alter actuator movement.",
                    "Monitor system response metrics, including:",
                    "    - Actuator positional drift due to unintended PWM signal distortions.",
                    "    - Variations in motor torque and speed under modulated EMI influence.",
                    "    - Loss of precise motor control due to interference-induced PWM signal alterations.",
                    "Perform parametric analysis:",
                    "    - Adjust modulation depth, frequency, and carrier wave power to identify optimal attack conditions.",
                    "    - Measure the delay and extent of unintended actuator movement.",
                    "    - Evaluate the effectiveness of different attack scenarios, such as sustaining a rotational offset or inducing oscillatory motion.",
                    "Compare results against baseline operation to quantify the impact of the Block & Rotate Waveform Attack.",
                    "Validate findings by cross-referencing with theoretical models and empirical data from similar interference studies.",
                "TA3 Exploit Steps",
                    "Prepare the experimental setup to test the Block & Rotate Waveform Attack on a physical PWM-controlled actuator.",
                    "Gather the necessary equipment:",
                    "    - Signal generator capable of producing AM CW signals.",
                    "    - Amplifier to enhance the interference signal’s strength.",
                    "    - Antenna optimized for coupling EMI into the PWM circuitry.",
                    "    - Measurement tools such as oscilloscopes and spectrum analyzers.",
                    "Identify the PWM signal characteristics:",
                    "    - Measure the nominal frequency and amplitude of the PWM control signal.",
                    "    - Conduct spectrum analysis to determine the actuator’s susceptibility to AM interference.",
                    "Position the interference antenna close to the PWM transmission medium (e.g., motor control wires or PCB traces).",
                    "Emit an AM CW signal at the determined resonant frequency with carefully controlled modulation parameters.",
                    "Gradually increase the signal power while monitoring actuator response:",
                    "    - Observe signs of blocked or unintended rotation in the motor.",
                    "    - Detect any loss of precision in PWM-based motor control.",
                    "    - Analyze oscilloscope waveforms for unintended PWM distortions.",
                    "Optimize attack parameters:",
                    "    - Adjust modulation depth and carrier frequency to maximize impact on motor position.",
                    "    - Identify the lowest power threshold needed to sustain the attack.",
                    "    - Record the optimal conditions where the motor enters a blocked or rotationally biased state.",
            ],
            
            associated_files=[],
            reference_urls=["https://www.usenix.org/system/files/sec22-dayanikli.pdf"],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
