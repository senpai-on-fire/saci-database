import os.path

from clorm import Predicate

'''
Modeling the adversarial examples attack
The modeled impact is: attackers can control the output of DNN models by exploiting known model parameters.
'''

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, DNNTracking
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate to define formal reasoning logic for vulnerabilities in deep neural networks (DNNs)
class DeepNeuralNetworkPred(Predicate):
    pass

class DeepNeuralNetworkVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The DNN component, vulnerable to adversarial example attacks
            component=DNNTracking(),
            # Input: Authenticated communication representing crafted adversarial inputs
            _input=AuthenticatedCommunication(),
            # Output: Authenticated communication leading to attacker-controlled or misclassified outputs
            output=AuthenticatedCommunication(),
            # Predicate for reasoning about adversarial vulnerabilities in DNNs
            attack_ASP=DeepNeuralNetworkPred,
            # Logic rules for evaluating adversarial attacks in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'adversarial_ml.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-20: Improper Input Validation",
                "CWE-285: Improper Authorization",
                "CWE-347: Improper Verification of Cryptographic Signature",
                "CWE-125: Out-of-Bounds Read",
                "CWE-326: Inadequate Encryption Strength",
                "CWE-400: Uncontrolled Resource Consumption",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-489: Active Debug Code"
            ]
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a DNN model
            if isinstance(comp, DNN):
                # Verify if the DNN model's source code and weights are known
                if comp.known_source and comp.known_weight:
                    # If both the source and weights are accessible, the model is vulnerable
                    # An attacker can craft adversarial examples to control the model's output
                    return True
        return False  # No vulnerability detected if conditions are not met


