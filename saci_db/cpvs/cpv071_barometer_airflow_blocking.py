from typing import List
from saci.modeling import CPV

from saci.modeling.device import Barometer, Serial, PWMChannel, ESC, MultiCopterMotor
from saci_db.devices.px4_quadcopter_device import PX4Controller 

from saci_db.vulns.airspeed_spoofing_vuln import BarometerObstructionVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.devices.ardupilot_quadcopter_device import ArduPilotController

class BarometerObstructionCPV(CPV):
    
    NAME = "The Obstruction Attack on Barometer Sensors"
    
    def __init__(self):
        super().__init__(
            required_components=[
                Barometer(),
                Serial(),     
                ArduPilotController(),  
                PWMChannel(),  
                ESC(),
                MultiCopterMotor(), 
            ],
            entry_component=Barometer(),
            exit_component=MultiCopterMotor(),
            
            vulnerabilities=[BarometerObstructionVuln(), ControllerIntegrityVuln()],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "None",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "None",
                "OperatingMode": "Stabilize",
            },
            
            attack_requirements=["Piece of tape or similar material to block airflow."],
            attack_vectors=[
                BaseAttackVector(
                    name="Physical Port Obstruction",
                    signal=None,
                    required_access_level="close proximity or physical",
                    configuration={
                        "duration": "Permanent",
                        "tool": "Adhesive Tape",
                    },
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Manipulation",
                    description="CPS is unable to maintain commanded altitude."
                )
            ],
            
            exploit_steps = [
                "TA1 Exploit Steps",
                    "Reverse-engineer the firmwaare to locate barometer driver and note any plausibility checks or sensor‑fusion fall‑backs.",
                
                "TA2 Exploit Steps",
                    "Implement a simulation of barometer sensor response to blocking.",
                    "Inject synthetic barometer signal into the control loop and measure controller response.",
                    "Observe altitude controller resposne.",     
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",
                
                "TA3 Exploit Steps",
                    "Use imaging tools and other techniques to catalog all components on the CPS.",
                    "Identify if a barometer sensor is present.",
                    "During steady flight/bench‑test, cover the barometer port with tape or a similar material to block airflow.",
                    "Log altitude estimate & motor RPM changes",
                    "Remove tape to verify recovery",
                ],

            associated_files=[],
            reference_urls=[],
        )
        
    def in_goal_state(self, state: GlobalState):
        pass