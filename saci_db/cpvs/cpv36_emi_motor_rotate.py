from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (PWMChannel, ESC, Motor)
from saci.modeling.state import GlobalState

from saci_db.vulns.pwm_spoofing_vuln import PWMSpoofingVuln

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.magnetic_attack_signal import MagneticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput

class EMIMotorBlockRotateCPV(CPV):
    
    NAME = "Block and Rotate Attack on Motors using EMI"
    
    def __init__(self):
        super().__init__(
            required_components=[
                PWMChannel(),                
                ESC(),
                Motor(),],
            entry_component=PWMChannel(),
            exit_component=Motor(),
            
            vulnerabilities=[PWMSpoofingVuln()],

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
            attack_impacts = [BaseAttackImpact(category='Manipulation of Control',
                                               description='Control the rotation direction of the motor')],

            exploit_steps=[
            "Determine the specific PWM-controlled actuator (i.e., Servo or DC motors).",
            "Measure the frequency, duty cycle, and amplitude of the legitimate PWM signal controlling the motor.",
            "Understand the relationship between the PWM duty cycle and the motor's behavior (e.g., position or speed).",
            "Set up a signal generator to produce a modulated signal that mimics the legitimate PWM signal's frequency and amplitude.",
            "Program the desired duty cycles corresponding to the specific motor behaviors you intend to enforce.",
            "Choose an antenna capable of efficiently coupling the modulated signal into the target's PWM circuitry.",
            "Place the antenna in close proximity to the PWM signal transmission path, such as the wires or PCB traces connecting the controller to the motor.",
            "Activate the signal generator to emit the modulated signal through the antenna.",
            "Adjust the signal's amplitude to ensure it overrides the legitimate PWM signal, effectively injecting the false actuation commands.",
            "Observe the motor's response to confirm it is following the injected commands.",
            "Fine-tune the frequency, duty cycle, and amplitude of the signal as necessary to maintain precise control over the motor.",
            "Record the conditions under which the attack was successful, including the specific frequency, duty cycles, and antenna positioning used."
            ],

            associated_files = [],
            reference_urls = ["https://www.usenix.org/system/files/sec22-dayanikli.pdf"],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass