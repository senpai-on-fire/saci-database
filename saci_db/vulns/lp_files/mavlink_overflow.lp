%%%%%%%%%%%%%% Mavlink overflow CPSV %%%%%%%%%%%%%% 
% The controller has a overflow in its mavlink protocol handling component
% This CPSV is hypothetical
% If the attack succeeds, the controller will crash

% Because of the action_gcs_setvalue(T, X) condition, we manage to chain the two attacks
% CPSV Mavlink enables action_gcs_setvalue(T, X), and that along with the vulnerability itself enables the cpsv attack
% 100 is just a placeholder for crashing input.
attack_cpsv_overflow(T) :- action_gcs_setvalue(T, 100).
primitive_make_controller_crash (T) :- attack_cpsv_overflow(T), not drone_crash(T).

action_make_controller_crash (T) :- primitive_make_controller_crash(T).

