from typing import List
from saci.modeling.device import OpticalFlowSensor, Serial, PWMChannel, ESC, MultiCopterMotor
from saci_db.devices.px4_quadcopter_device import PX4Controller
from saci.modeling import CPV
from saci_db.vulns.opticalflow_spoofing_vuln import OpticalFlowSpoofingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.image_attack_signal import ImageAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact


class ProjectorOpticalFlowCPV(CPV):
    
    NAME = "The Projector Spoofing on Optical Flow Camera Sensors"
    
    def __init__(self):
        super().__init__(
            required_components=[
                OpticalFlowSensor(),
                Serial(),            
                PX4Controller(),   
                PWMChannel(),  
                ESC(),
                MultiCopterMotor(), 
            ],
            entry_component=OpticalFlowSensor(),
            exit_component=MultiCopterMotor(),
            
            vulnerabilities=[OpticalFlowSpoofingVuln(), ControllerIntegrityVuln()],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "None",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "None",
                "Operating mode": "Hold",
            },
            
            attack_requirements=["Projector or Laser-based spoofing device"],
            attack_vectors=[
                BaseAttackVector(
                    name="Optical Flow Spoofing Signal Injection",
                    signal=ImageAttackSignal(
                        src=ExternalInput(),
                        dst=OpticalFlowSpoofingVuln().component,
                        modality="image",
                    ),
                    required_access_level="Physical",
                    configuration={"duration": "Permanent"},
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Manipulation",
                    description="CPS drifts uncontrollably or exhibits unintended lateral movement targeted by the attackers."
                )
            ],
            
            exploit_steps=[
                "Position the spoofing device in the UAV's optical flow sensor field.",
                "Project high-contrast patterns using a laser or projector.",
                "Move the projected pattern to mislead corner detection algorithms.",
                "Observe the drone drift following the displacement of the projected pattern.",
            ],
            
            associated_files=[],
            reference_urls=["https://www.usenix.org/system/files/conference/woot16/woot16-paper-davidson.pdf"],
        )
        
    def in_goal_state(self, state: GlobalState):
        pass