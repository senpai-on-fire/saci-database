from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import Controller, GCS, Wifi, Telemetry, PWMChannel, ESC, MultiCopterMotor, Mavlink, ExpressLRSBackpack
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.ardupilot_flip_param_overwrite import ExpressLRSFirmwareOverwriteVuln
from saci_db.devices.ardupilot_quadcopter_device import ArduPilotController


class AttitudeFlipParameterManipulation(CPV):

    NAME = "Parameter Manipulation via Network Interface - Attitude Control"

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
                MultiCopterMotor(),         
            ],
            entry_component=Wifi(),
            exit_component=ArduPilotController(),

            vulnerabilities=[
                ExpressLRSFirmwareOverwriteVuln()
            ],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Stationary",
                "OperatingMode": "STABILIZE"
            },

            attack_requirements=[
                "Computer with network access",
                "Local Wi-Fi access to target network",
                "Access to parameter configuration interface",
                "Knowledge of attitude control parameters"
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Parameter Manipulation via Network Interface",
                    signal=PacketAttackSignal(
                        src=ExternalInput(),
                        dst=Telemetry(),
                        modality="network_packets"
                    ),
                    required_access_level="Remote",
                    configuration={
                        "payload": {
                            "param_names": ["ATC_RAT_RLL_FF", "ATC_RATE_R_MAX"],
                            "param_values": ["0.43", "11"],
                            "mode_change": "FLIP"
                        },
                        "protocol": "MAVLink",
                        "port": "14550"
                    }
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Loss of Control",
                    description="Manipulation of attitude control parameters combined with mode changes leads to unrecoverable flight instability and potential system failure."
                )
            ],

            exploit_steps=[
                "TA1 Exploit Steps",
                    "Extract firmware from target flight controller",
                    "Analyze attitude control parameter validation logic",
                    "Identify critical parameter ranges and dependencies",
                    "Model control system behavior under parameter manipulation",
                    "Map parameter impact on flight dynamics",
                    "Document potential unstable parameter combinations",

                "TA2 Exploit Steps",
                    "Configure software-in-the-loop simulation environment",
                    "Record baseline parameter values and flight behavior",
                    "Test parameter modifications in simulation",
                    "Validate flight instability scenarios",
                    "Document recovery procedures and failure modes",
                    "Analyze system logs during parameter changes",
                    "Verify attack persistence across flight modes",

                "TA3 Exploit Steps",
                    "Turn on controller and drone system",
                    "Connect to target network interface",
                    "Launch MAVProxy with appropriate connection parameters",
                    "Record original attitude control parameter values",
                    "Verify current flight mode and system status",
                    "Execute parameter modifications",
                    "Trigger mode change to induce instability",
                    "Document system response and behavior",
            ],

            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/owlet-taskboard/blob/main/CPVs/IVV_Feedback/PASS/HII-GS0409380007-CPV015.docx"
            ]
        )

    def in_goal_state(self, state: GlobalState):
        # TODO: Implement goal state logic if required
        pass