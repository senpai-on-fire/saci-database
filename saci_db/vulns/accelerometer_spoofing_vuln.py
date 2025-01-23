import os.path

from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device
from saci.modeling.device.accelerometer import AccelerometerSensor
from saci.modeling.communication import UnauthenticatedCommunication

class AccelerometerSpoofingPred(Predicate):
    pass

class AccelerometerSpoofingVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            component=AccelerometerSensor(),
            # Input here would be the unauthenticated, spoofed accelerometer signals
            _input=UnauthenticatedCommunication(),
            # Output would be erroneous navigation decisions based on spoofed accelerometer signals (because of faulty heading data)
            output=UnauthenticatedCommunication(),
            attack_ASP=AccelerometerSpoofingPred,
            
            # Needs to be Updated
            # rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'accelerometer_spoofing.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            # Check if the device uses a accelerometer sensor for navigation and if the accelerometer signals are not authenticated
            if isinstance(comp, AccelerometerSensor) and not comp.authenticated:
                return True

        return False