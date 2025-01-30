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
                "Operating mode": "Mission",},

            attack_requirements = ["RF Signal Generators", "Amplifiers", "Near-Field Probes", "Loop Antennas or Coils "],
            attack_vectors = [BaseAttackVector(name="Electromagnetic Signals Interference", 
                                               signal=MagneticAttackSignal(src=ExternalInput(), dst=PWMChannel()),
                                               required_access_level="Remote",
                                               configuration={"duration": "permanent"},
                                                )],  
            attack_impacts = [BaseAttackImpact(category='Denial of control',
                                               description='Motor stops responding to legititame PWM commands')],

            exploit_steps=[
            "Determine the specific PWM-controlled actuator (e.g., Servo or DC motors).",
            "Measure the frequency and amplitude of the legitimate PWM signal controlling the motor.",
            "Identify the resonant frequency of the motor's PWM circuitry to enhance the effectiveness of the attack.",
            "Set up a signal generator to produce a continuous wave (CW) signal at the identified resonant frequency of the target PWM circuitry.",
            "Adjust the amplitude of the CW signal to a level sufficient to induce a voltage comparable to the PWM signal's amplitude.",
            "Choose an antenna capable of efficiently coupling the CW signal into the target's PWM circuitry.",
            "Ensure the antenna is designed to operate effectively at the chosen frequency.",
            "Place the antenna in close proximity to the physical transmission medium of the PWM signal, such as the wires or PCB traces connecting the controller to the motor.",
            "Ensure the antenna orientation maximizes electromagnetic coupling with the target circuitry.",
            "Activate the signal generator to emit the CW signal through the antenna.",
            "Gradually increase the signal power while monitoring the motor's response.",
            "Observe for signs of disruption, such as the motor ceasing to respond to legitimate PWM commands.",
            "Continuously monitor the motor to confirm the effectiveness of the attack.",
            "If necessary, fine-tune the frequency and amplitude of the CW signal to maintain the blocking effect.",
            "Record the conditions under which the attack was successful, including the specific frequency, amplitude, and positioning used."
            ],

            associated_files = [],
            reference_urls = ["https://www.usenix.org/system/files/sec22-dayanikli.pdf"],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass