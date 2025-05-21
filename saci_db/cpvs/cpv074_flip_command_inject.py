from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import Controller, GCS, Wifi, Telemetry, PWMChannel, ESC, Motor, Mavlink, ExpressLRSBackpack
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.mavlink_mitm_vuln import MavlinkMitmVuln
from saci_db.devices.ardupilot_quadcopter_device import ArduPilotController

class FlipAtLowAltitudeCPV(CPV):

    NAME = "Trigger FLIP Mode Below Safety Altitude"

    def __init__(self):
        super().__init__(
            required_components=[
                GCS(),            
                Mavlink(),        
                Wifi(),    
                ExpressLRSBackpack(),    
                ArduPilotController(),     
                PWMChannel(),     
                ESC(),            
                Motor(),          
            ],
            entry_component=Wifi(),
            exit_component=Motor(), 

            vulnerabilities=[MavlinkMitmVuln],

            initial_conditions={
                "Position": "Any",
                "Altitude": "< 10 meters",
                "OperatingMode": "STABILIZE",
                "DroneState": "Flying",
                "RemoteController": "Connected",
                "Safety": "Off"
            },

            attack_requirements=[
                "Attacker laptop with MAVProxy installed",
                "Access to ExpressLRS TX Backpack Wi-Fi (default password: 'expresslrs')",
                "Knowledge of MAVLink protocol",
                "Armed and airborne drone in STABILIZE mode under 10m altitude"
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="FLIP Mode Command Injection via MAVLink",
                    signal=PacketAttackSignal(
                        src=ExternalInput(),
                        dst=Telemetry(),
                        modality="network_packets"
                    ),
                    required_access_level="Remote",
                    configuration={
                        "payload": {
                            "mavlink_command": "mode FLIP"
                        },
                        "protocol": "MAVLink",
                        "port": "14550"
                    }
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Loss of Control",
                    description="Drone attempts a flip maneuver while flying below the safe altitude, resulting in crash or system damage."
                )
            ],

            exploit_steps=[
                "TA3 Exploit Steps",
                    "Extract firmware from STM32H743 chip using EXPLODE tool",
                    "Confirm firmware is based on outdated ArduPilot release",
                
                "TA1/TA2 Exploit Steps",
                    "Analyze firmware using Taveren to generate state machine",
                    "Verify altitude safety check is missing before FLIP mode entry",
                    "Simulate flip behavior below 10m in Gazebo; observe crash",

                "TA4 Exploit Steps",
                    "Power on drone and transmitter, ensure STABILIZE mode is set",
                    "Connect attacker laptop to ExpressLRS Wi-Fi ('expresslrs')",
                    "Use MAVProxy to connect to drone and execute: mode FLIP",
                    "Observe motor oscillation consistent with flip behavior"
            ],

            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/owlet-taskboard/blob/main/CPVs/IVV_Feedback/PASS/HII-GS0409380007-CPV013.docx"
            ]
        )

    def in_goal_state(self, state: GlobalState):
        # TODO: Implement goal state logic if required
        pass
