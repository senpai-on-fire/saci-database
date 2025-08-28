
from saci.modeling import CPV
from saci.modeling.device import (
    Controller,
    Wifi,
    Mavlink,
    Motor,
)
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.mavlink_mitm_vuln import MavlinkMitmVuln
from saci_db.vulns.wifi_knowncreds_vuln import WifiKnownCredsVuln


class RCMotorJitterCPV(CPV):
    NAME = "RC Throttle Conflict via MAVLink"

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
                "Altitude": "Any",
                "OperatingMode": "STABILIZE",
                "DroneState": "Flying",
                "RemoteController": "Connected",
                "Safety": "Off",
            },
            
            attack_requirements=[
                "Laptop with MAVProxy or similar MAVLink injection tool",
                "Access to ExpressLRS TX Backpack Wi-Fi (default password: 'expresslrs')",
                "Knowledge of RC channel mappings (e.g., CH3 = Throttle)",
                "Target drone flying in STABILIZE mode",
            ],
            
            attack_vectors=[
                BaseAttackVector(
                    name="Throttle Override via RC MAVLink Command",
                    signal=PacketAttackSignal(
                        src=Wifi(), dst=Controller(), modality="network_packets"
                    ),
                    required_access_level="Remote",
                    configuration={
                        "payload": {"mavlink_command": "rc 3 1900"},
                        "protocol": "MAVLink",
                        "port": "14550",
                    },
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Loss of Control",
                    description="Conflicting throttle commands from RC and MAVLink create motor jitter, potentially causing flight instability or crash.",
                )
            ],
            
            exploit_steps=[                
                "TA1/TA2 Exploit Steps",
                    "Run Gazebo simulation with ArduPilot and simulate 'rc 3 1900' injection",
                    "Observe conflicting motor behavior under RC transmitter control",
                    "Theorize and analyze potential loss of control due to race condition",
                "TA3 Exploit Steps",
                    "Use EXPLODE tool to identify STM32H743 and extract firmware",
                    "Confirm ArduPilot-based firmware and version is outdated",
                    "Power on controller and drone, enter STABILIZE mode",
                    "Connect attacker laptop to ExpressLRS Wi-Fi ('expresslrs')",
                    "Launch MAVProxy and send: rc 3 1900",
                    "Observe jittery motor behavior due to throttle race",
                    "Send: rc 3 0 to reset command",
                    "Disarm drone and conclude experiment",
            ],
            
            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/owlet-taskboard/blob/main/CPVs/IVV_Feedback/PASS/HII-GS0409380007-CPV014.docx"
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO: Define criteria for successful exploitation if required
        pass
