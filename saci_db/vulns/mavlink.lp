
%%%%%%%%%%%%%% Mavlink authentication CPSV %%%%%%%%%%%%%% 
% If the attack succeeds, then one can achieve arbitrary command control with the attack
% This is that a CPSV attack achieves a primitive
0 {attack_cpsv_mavlink(T) : time(T)} 10 :- time(T).
primitive_mavcommandcontrol(T) :- attack_cpsv_mavlink(T).

% If we have mavcommandcontrol, then we can send an arbitrary command from the set.
% This is that a primitive enables an action
%1 {action_gcs_setvalue(T, X) : speed(X)} 1 :- primitive_mavcommandcontrol(T).
1 {action_gcs_setdisarm(T) ; action_gcs_settakeoff(T) ; action_gcs_setvalue(T, X) : speed(X); action_gcs_setvalue(T, 100) ; action_gcs_setland(T)} 1 :- primitive_mavcommandcontrol(T), not drone_crash(T), time(T).

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

