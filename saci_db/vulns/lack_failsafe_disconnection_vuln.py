import os.path

from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.attack import BaseAttackVector, BaseAttackSignal, BaseCompEffect
from saci.modeling.device import Serial, Controller, Device


class LackFailsafeDisconnectionPred(Predicate):
    pass

class LackFailsafeDisconnectionVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            component = Controller(),

            _input=None,

            output=None,

            attack_ASP=LackFailsafeDisconnectionPred,

            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'lack_failsafe_disconnection.lp'),

            associated_cwe = [],

            attack_vectors_exploits = [
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="USB Disconnection",
                            signal=BaseAttackSignal(src=Serial(), dst=Controller(),
                            modality="USB Connection"),
                            required_access_level="Physical",
                        )
                    ],
                    "related_cpv": ["UsbCableUnplugCPV"],
                    "comp_attack_effect": BaseCompEffect(
                        category="Denial of Service",
                        description="After the physical connection is disconnected, the CPS does not respond to any commands."
                    ),
                    "exploit_steps": [
                        "Physically connect to the CPS device through an exposed serial connection port (like USB-C).",
                        "Use a terminal emulator to view the serial communication.",
                        "Verify that remote commands (via Wifi) still work.",
                        "Disconnect the physical serial connection and attempt to issue a remote command.",
                        "Observe if remote commands are responsive after disconnection."
                    ]
                }
            ]

        )

    def exists(self, device: Device) -> bool:
        #If a device has some kind of Serial communication, there is a chance of unexpected behavior when the connection is broken
        for comp in device.components:
            if isinstance(comp, Serial): 
                return True   
        return False