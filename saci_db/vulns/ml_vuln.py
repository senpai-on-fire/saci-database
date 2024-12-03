import os.path

from clorm import Predicate

'''''
Modeling the adversarial examples attack
The modeled imapct is: attackers can control the output of DNN models
'''''
from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, ObjectTracking
from saci.modeling.communication import AuthenticatedCommunication

class DeepNeuralNetworkPred(Predicate):
    pass

class DeepNeuralNetworkVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # Assuming that ObjectTracking is a DNN model
            component=ObjectTracking(),
            # The input to a deauth attack is unauthenticated 
            _input=AuthenticatedCommunication(),
            # The output is the disconnection 
            output=AuthenticatedCommunication(),
            attack_ASP=DeepNeuralNetworkPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'deepneuralnetwork.lp')
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            # Check if the component have object tracking model
            if isinstance(comp, ObjectTracking):
                if comp.known_source and comp.known_weight:
                    # If we can dump the source code and the weight of the model, it's vulnerable
                    # The attacker can control the output of the model
                    return True
        return False


