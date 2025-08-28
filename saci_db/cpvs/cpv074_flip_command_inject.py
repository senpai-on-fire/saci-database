from saci.modeling import CPV
from saci.modeling.device import (
    Wifi,
    Mavlink,
    Motor,
    Controller,
)
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.mavlink_mitm_vuln import MavlinkMitmVuln
from saci_db.vulns.wifi_knowncreds_vuln import WifiKnownCredsVuln


class FlipAtLowAltitudeCPV(CPV):
    NAME = "Trigger FLIP Mode Below Safety Altitude"

    def __init__(self):
        super().__init__(
            required_components=[
                Wifi(),  # This is the entry component (Required)
                Mavlink(),  # This is a vulnerable required component (Required)
                Controller(),  # Changed from PX4Controller() to Controller() for generalization (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(),  # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            entry_component=Wifi(),
            exit_component=Motor(),
            vulnerabilities=[WifiKnownCredsVuln(), MavlinkMitmVuln()],
            initial_conditions={
                "Position": "Any",
                "Altitude": "< 10 meters",
                "OperatingMode": "STABILIZE",
                "DroneState": "Flying",
                "RemoteController": "Connected",
                "Safety": "Off",
            },
            attack_requirements=[
                "Attacker laptop with MAVProxy installed",
                "Access to ExpressLRS TX Backpack Wi-Fi (default password: 'expresslrs')",
                "Knowledge of MAVLink protocol",
                "Armed and airborne drone in STABILIZE mode under 10m altitude",
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="FLIP Mode Command Injection via MAVLink",
                    signal=PacketAttackSignal(src=Wifi(), dst=Controller(), modality="network_packets"),
                    required_access_level="Remote",
                    configuration={
                        "payload": {"mavlink_command": "mode FLIP"},
                        "protocol": "MAVLink",
                        "port": "14550",
                    },
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Loss of Control",
                    description="Drone attempts a flip maneuver while flying below the safe altitude, resulting in crash or system damage.",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Analyze firmware using Taveren to generate state machine",
                "Verify altitude safety check is missing before FLIP mode entry",
                "TA2 Exploit Steps",
                "Simulate flip behavior below 10m in Gazebo; observe crash",
                "TA3 Exploit Steps",
                "Extract firmware from STM32H743 chip using EXPLODE tool",
                "Confirm firmware is based on outdated ArduPilot release",
                "Power on drone and transmitter, ensure STABILIZE mode is set",
                "Connect attacker laptop to ExpressLRS Wi-Fi ('expresslrs')",
                "Use MAVProxy to connect to drone and execute: mode FLIP",
                "Observe motor oscillation consistent with flip behavior",
            ],
            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/owlet-taskboard/blob/main/CPVs/IVV_Feedback/PASS/HII-GS0409380007-CPV013.docx"
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO: Implement goal state logic if required
        pass
