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
from saci.modeling.device import ESC, PWMChannel, MultiCopterMotor

class EMIMotorBlockCPV(CPV):
    
    NAME = "The Block PWM Signals Attack on Motors using EMI"
    
    def __init__(self):
        super().__init__(
            required_components=[
                PWMChannel(),  
                ESC(),
                MultiCopterMotor()
                ],
                
            entry_component=PWMChannel(),
            exit_component=MultiCopterMotor(),
            
            vulnerabilities=[PWMSpoofingVuln(), LackEMIPWMShieldingPred()],

            goals = [],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any", 
                "Environment": "Any", 
                "RemoteController": "On", 
                "CPSController": "Moving",
                "OperatingMode": "Manual or Mission",
                },

            attack_requirements = ["RF Signal Generators", "Amplifiers", "Near-Field Probes", "Loop Antennas or Coils "],
            attack_vectors = [BaseAttackVector(name="Electromagnetic Signals Interference", 
                                               signal=MagneticAttackSignal(src=ExternalInput(), dst=PWMChannel()),
                                               required_access_level="Remote",
                                               configuration={"duration": "permanent"},
                                                )],  
            attack_impacts = [BaseAttackImpact(category='Denial of Control',
                                               description='Motor stops responding to legititame PWM commands')],

            exploit_steps = {
                "TA1 Exploit Steps": [
                    "Develop a simulation model to analyze the impact of the Block Waveform Attack on PWM-controlled actuators.",
                    "The model must include:",
                    "    - Controller logic algorithm governing actuator behavior.",
                    "    - PWM signal generation and its role in motor control.",
                    "    - Electromagnetic interference (EMI) injection model simulating continuous wave (CW) signals.",
                    "    - Actuator response to disrupted PWM signals.",
                    "    - Environmental influences on EMI propagation and interference effectiveness.",
                    "Identify key parameters influencing the attack:",
                    "    - The PWM signal frequency and amplitude under normal operation.",
                    "    - The resonant frequency of the PWM circuitry that enhances attack effectiveness.",
                    "    - The required power level of the interfering signal to disrupt motor operation.",
                    "Simulate the effects of a continuous CW signal interfering with the legitimate PWM control signal:",
                    "    - Observe system behavior under different interference power levels.",
                    "    - Determine the minimum power required to block the PWM signal.",
                    "    - Identify potential mitigation factors, such as signal filtering or shielding."
                ],
                "TA2 Exploit Steps": [
                    "Implement the simulation model using appropriate electromagnetic and control system analysis tools.",
                    "Configure the simulation environment with realistic actuator parameters and PWM characteristics.",
                    "Simulate the attack by injecting a CW signal at the resonant frequency of the PWM circuitry.",
                    "Monitor system response metrics, including:",
                    "    - Changes in motor torque and speed.",
                    "    - Signal distortions in the PWM control waveform.",
                    "    - Actuator failure or response lag under varying interference conditions.",
                    "Perform parametric analysis:",
                    "    - Adjust CW signal amplitude and frequency to determine the optimal attack parameters.",
                    "    - Evaluate the attack’s effectiveness at different distances between the interference source and the actuator circuitry.",
                    "Compare results against baseline operation to quantify the impact of the Block Waveform Attack.",
                    "Validate findings by cross-referencing with theoretical models and prior research."
                ],
                "TA3 Exploit Steps": [
                    "Prepare the experimental setup to test the Block Waveform Attack on a physical PWM-controlled actuator.",
                    "Gather the necessary equipment:",
                    "    - Signal generator capable of producing CW signals in the target frequency range.",
                    "    - Amplifier to enhance the interference signal’s strength.",
                    "    - Antenna optimized for coupling EMI into the PWM circuitry.",
                    "    - Measurement tools such as oscilloscopes and spectrum analyzers.",
                    "Identify the PWM signal characteristics:",
                    "    - Measure the operating frequency and amplitude of the legitimate PWM control signal.",
                    "    - Conduct spectrum analysis to determine the actuator’s susceptibility to external EMI.",
                    "Position the interference antenna close to the PWM transmission medium (e.g., motor control wires or PCB traces).",
                    "Emit a CW signal at the determined resonant frequency and gradually increase its power level.",
                    "Observe the motor’s response to the interference:",
                    "    - Loss of response to legitimate PWM commands.",
                    "    - Unexpected motor halting or erratic behavior.",
                    "    - Signal distortions detected on an oscilloscope.",
                    "Optimize attack parameters:",
                    "    - Adjust signal frequency and power to maintain effective blocking.",
                    "    - Record the conditions where interference successfully disrupts motor operation.",
                ],
            },

            associated_files = [],
            reference_urls = ["https://www.usenix.org/system/files/sec22-dayanikli.pdf"],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass