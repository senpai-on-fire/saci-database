from typing import List, Type

from saci.modeling import CPV
from saci.modeling.communication import ExternalInput

from saci_db.vulns.gcs_rf_blocking_vuln import GCSRFBlockingVuln
from saci_db.vulns.lack_wifi_auth_vuln import LackWifiAuthenticationVuln
from saci_db.vulns.lack_wifi_encryption_vuln import LackWifiEncryptionVuln


from saci.modeling.attack.radio_attack_signal import RadioAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact


from saci.modeling.device import (
    GCS,
    Mavlink,
    Wifi,
    TelemetryHigh,
    SikRadio,
    ESC,
    PWMChannel,
    MultiCopterMotor,
    ExpressLRSBackpack,
    Motor,
    Controller
)
from saci.modeling.state import GlobalState

from saci_db.devices.ardupilot_quadcopter_device import ArduPilotController


class RFBlockingCPV(CPV):
    NAME = "The RF signal blocking via a shielded chamber results in blocking the heartbeat signal, trigerring the fail safe mechanism"

    def __init__(self):
        super().__init__(
            
            required_components=[
                GCS(), # This is the entry component (Required)
                Mavlink(), # This is a vulnerable required component (Required)
                Controller(), # Changed from PX4Controller() to Controller() for generalization (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            
            entry_component=GCS(),
            exit_component=Motor(),
            
            vulnerabilities=[GCSRFBlockingVuln()],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Shielded Chamber",
                "RemoteController": "On",
                "CPSController": "Active",
                "Operating mode": "Manual or Semi-Autonomous",
            },
            
            attack_requirements=[
                "Shielded Chamber. eg:Ramsey Faraday enclosure",
                "Physical Access",
                "Fail-safe mechanism",
                "Drone is powered on and armed",
            ],
            
            attack_vectors=[
                BaseAttackVector(
                    name="RF Blocking Attack",
                    required_access_level="Physical",
                    configuration={
                        "attack_method": "RF blocking",
                        "target": "CPS communication channel",
                    },
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Flight control enters land mode and overrides motor speed.",
                )
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Analyze the firmware of the controller and verify it is running ArduPilot with a fail safe mechanism when losing the MAVlink heartbeat signal",
                "TA2 Exploit Steps",
                    "Do a simulation of the drone that includes the following:",
                    "   1- The ArduPilot control logic",
                    "   2- The MAVlink with the heartbeat signal",
                    "Run the simulation then at time t stop the MAVlink from receiving the heartbeat signal",
                    "At t+30 seconds, verify that the fail safe mechanism is triggered and report the fail safe mechanism deployed by the drone to TA3",
                "TA3 Exploit Steps",
                    "Reverse Engineering: "
                    "   1- Verify that the drone uses an RF module for remote control",
                    "Replicate the attack: ",
                    "   Note:",
                    "       The following steps would be useful if the failsafe mechanism is forced landing as it can be heard through the Ramsey box. Other techniques would be necessary to verify other fail safe mechanisms.",
                    "   Components:",
                    "       1- Shielding Chamber (eg : Ramsey Faraday enclosure)",
                    "       2- Remote Controller",
                    "   Steps:        1.	Place the drone in an open Ramsey box.",
                    "       2.	Turn on the controller.",
                    "       3.	Turn on the drone.",
                    "       4.	Turn off the drone safety.",
                    "       5.	On the controller, arm the drone and observe that the motors begin to spin.",
                    '       6.	On the controller, use the shoulder switch to put the drone in "Stabilize" mode.',
                    '       7.	On the controller, move the throttle to the max position to begin a "flight".',
                    "       a.	Any position should suffice, but max throttle is easier to hear through the box.",
                    "       8.	Close and latch the Ramsey box.",
                    "       9.	Wait for the transmitter to lose signal (the signal bars will disappear), and then wait additional 30 seconds.",
                    "       10.	Observe the drone’s motors RPM decrease and then stop as the drone has switched to landing mode. (or whatever failsafe mechanism TA2 reported)",
                    "       11.	Using the controller, attempt to arm the drone again.",
                    "       12.	Observer that the drone will not arm.",
            ],
            associated_files=[
                "https://github.com/senpai-on-fire/owlet-taskboard/blob/main/CPVs/HII-GS0409380007-CPV008/HII-GS0409380007-CPV008.mp4"
            ],
            reference_urls=[
                "https://github.com/senpai-on-fire/owlet-taskboard/blob/main/CPVs/IVV_Feedback/PASS/HII-GS0409380007-CPV008-202503061.docx"
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO: ?
        pass
        # return state.has_property("CommunicationLoss", True)
