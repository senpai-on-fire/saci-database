import os.path

from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import GyroscopeHWPackage, GyroscopeHWTechnology, GyroscopeHWCircuit, Device
from saci.modeling.communication import BaseCommunication

class RockingDronesVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            component=GyroscopeHWTechnology,
            _input=None, # Input can be redefined by the attacker 
            output=BaseCommunication(), # TODO: still need to express how this sensor connects with other components
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            if isinstance(comp, GyroscopeHWTechnology) and comp.chip_type == "MEMS":
                return True

            if isinstance(comp, GyroscopeHWPackage):
                vuln_sensor_list = ['L3G4200D', 'L3GD20', 'LSM330', 'LPR5150AL', 'LPY503AL', 'MPU3050', 'MPU6000', 'MPU6050', 'MPU6500', 'MPU9150', 'IMU3000', 'ITG3200', 'IXZ650', 'ADXRS610', 'ENC-03MB']
                if comp.chip_name in vuln_sensor_list:
                    return True
            
            if isinstance(comp, GyroscopeHWCircuit):
                if comp.SignalProcessingChain != "EKF":
                    return True