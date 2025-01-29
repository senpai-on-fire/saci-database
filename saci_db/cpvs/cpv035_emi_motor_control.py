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

class EMIMotorFullControlCPV(CPV):
    
    NAME = "The Full Control on PWM Signals to Motors using EMI"
    
    def __init__(self):
        super().__init__(
            required_components=[
                PX4Controller(),   
                PWMChannel(),  
                ESC(),
                MultiCopterMotor(),  
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

            attack_requirements = ["RF Signal Generator", "Power Amplifier", "Directional Antenna", "Spectrum Analyzer"],
            attack_vectors = [BaseAttackVector(name="Electromagnetic Signals Interference", 
                                               signal=MagneticAttackSignal(src=ExternalInput(), dst=PWMChannel()),
                                               required_access_level="Remote",
                                               configuration={"duration": "permanent"},
                                                )],  
            attack_impacts = [BaseAttackImpact(category='Denial of Service',
                                               description='Controller cannot retrieve the correct IMU data')],

            exploit_steps=[
            "Determine the specific PWM-controlled actuator (i.e., Servo or DC motors).",
            "Measure the frequency and amplitude of the legitimate PWM signal controlling the motor.",
            "Identify the duty cycle corresponding to specific motor positions or speeds.",
            "Set up a signal generator to produce a continuous wave (CW) signal at a frequency that resonates with the target motor's PWM circuitry.",
            "Modulate the CW signal to mimic the desired PWM duty cycle that corresponds to the motor position or speed you intend to enforce.",
            "Choose an antenna capable of efficiently coupling the modulated signal into the target's PWM circuitry.",
            "Place the antenna in close proximity to the PWM signal transmission path, such as the wires or PCB traces connecting the controller to the motor.",
            "Activate the signal generator to emit the modulated signal through the antenna.",
            "Adjust the signal's amplitude to ensure it overrides the legitimate PWM signal, effectively injecting the false actuation command.",
            "Observe the motor's response to confirm it is following the injected commands.",
            "Fine-tune the frequency, modulation, and amplitude of the signal as necessary to maintain control over the motor.",
            "Record the conditions under which the attack was successful, including the specific frequency, modulation parameters, and antenna positioning used."
            ],

            associated_files = [],
            reference_urls = ["https://www.usenix.org/system/files/sec22-dayanikli.pdf"],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass