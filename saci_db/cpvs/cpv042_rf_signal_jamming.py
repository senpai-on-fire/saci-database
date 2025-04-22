from typing import List, Type

from saci.modeling import CPV
from saci.modeling.communication import ExternalInput

from saci_db.vulns.rf_interference_vuln import RFInterferenceVuln
from saci_db.vulns.lack_wifi_auth_vuln import LackWifiAuthenticationVuln
from saci_db.vulns.lack_wifi_encryption_vuln import LackWifiEncryptionVuln


from saci.modeling.attack.radio_attack_signal import RadioAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact


from saci.modeling.device import GCS, Mavlink, Wifi, TelemetryHigh, SikRadio, ESC, PWMChannel, MultiCopterMotor
from saci.modeling.state import GlobalState

from saci_db.devices.ardupilot_quadcopter_device import ArduPilotController


class RFJammingCPV(CPV):

    NAME = "The RF Jamming via External Signal Interference"

    def __init__(self):
        super().__init__(
            required_components=[
                GCS(),
                SikRadio(),   
                Mavlink(),  
                TelemetryHigh(),            
                ArduPilotController(), # DJI also + can work with PX4 potentially
                PWMChannel(),  
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=GCS(),        
            exit_component=MultiCopterMotor(), 

            vulnerabilities=[RFInterferenceVuln(), LackWifiAuthenticationVuln(), LackWifiEncryptionVuln()],

            initial_conditions={
                "Position": "Within communication range of the target drone",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Active",
                "Operating mode": "Manual or Semi-Autonomous",
            },

            attack_requirements=[
                "RF signal generator or jammer",
                "Knowledge of the CPS's communication frequency (e.g., 2.4 GHz or 5 GHz)",
                "Proximity to the CPS's operating area",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="RF Jamming Attack",
                    signal=RadioAttackSignal(
                        src=ExternalInput(),
                        dst=SikRadio(),
                    ),
                    required_access_level="Proximity",
                    configuration={
                        "attack_method": "Broadband RF jamming",
                        "frequency_range": "2.4 GHz or 5 GHz",
                        "hardware": "HackRF",
                        "target": "CPS communication channel",
                    },
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Disrupts telemetry and control signals, causing the CPS to lose communication with its controller."
                )
            ],

            exploit_steps = [
                "TA1 Exploit Steps",
                    "Identify the communication frequencies used between the Ground Control Station (GCS) and the drone running ArduPilot.",
                    "Common frequency bands include:",
                    "    - 2.4 GHz (Wi-Fi, telemetry control).",
                    "    - 5.8 GHz (video transmission).",
                    "Use software-defined radio (SDR) tools such as HackRF One or RTL-SDR to analyze real-time frequency spectrums.",
                
                "TA2 Exploit Steps",
                    "Select and configure appropriate RF jamming equipment based on identified frequencies.",
                    "    - Choose between omnidirectional or directional jammers depending on the target environment.",
                    "    - Adjust transmission power to effectively disrupt the drone-GCS link while minimizing unintended interference.",
                    "Deploy the jammer within range of the drone’s operational zone to maximize disruption effectiveness.",
            
                "TA3 Exploit Steps",
                    "Activate the jammer and observe the drone’s behavior in response to communication loss.",
                    "After getting datMonitor potential outcomes based on fail-safe configurations, including:",
                    "    - Hovering in place due to loss of command signals.",
                    "    - Initiating return-to-home (RTH) mode if GPS is available.",
                    "    - Forced landing if the drone enters failsafe mode.",
                    "Record the impact on network performance using iperf3 to measure throughput disruptions.",
                    "Verify the jamming effects by analyzing telemetry dropouts and link quality reduction using tools like airodump-ng or Wireshark.",
                ],

            associated_files=[],
            reference_urls=[
                "https://d-fendsolutions.com/blog/types-of-jammers/",
                "https://d-fendsolutions.com/blog/suitability-of-jammers-for-rogue-drone-mitigation-at-airports/",
                "https://d-fendsolutions.com/blog/when-a-drone-is-jammed/",
                "https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEF%20CON%2024%20-%20Aaron-Luo-Drones-Hijacking-Multi-Dimensional-Attack-Vectors-And-Countermeasures-UPDATED.pdf"
            ]
        )

    def in_goal_state(self, state: GlobalState):
        return state.has_property("CommunicationLoss", True)