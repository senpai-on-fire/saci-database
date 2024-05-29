% TODO: move the following 2 lines to somewhere else
speed(0..1).
time(1..10).

% generating

state_drone_takeoff(1).

1 {drone_crash(T); state_drone_takeoff(T)} 1 :- time(T).

%% we need a rule to filter out the case that drone turns to crash without any reason

%% Goal: Hypothesize CPV, i.e., to chain CPSVs into possible CPVs
%% And then human will generate an CPV attack
%% And then we can use this to verify that the attack should work across components/CPSVs
%% Finally we can simulate or directly test on a machine

%%%% If we uncomment this rule, we will forbidden directly setting speed to 0 while flying.
% :- action_gcs_setvalue(T, 0), state_drone_takeoff(T), time(T).


% NOTE: The actions need to be concretized by the CPSV
% The CPSV should tell how to enforce the action.
% TODO: it should be that state_controller_crash(T+1) :- ANY_CONTROLLER_STATE + action_make_controller_crash(T),
% but I don't know how to represent it now
state_controller_crash(T+1) :- action_make_controller_crash(T).


%%%%%%%%%%%%% Controller state %%%%%%%%%%
% Controller will output 0 for motor speed setting if it crashes
output_controller_setmotorvalue(T, 0) :- state_controller_crash(T).


%%%%%%%%%%%% Drone state %%%%%%%%%%%%%
% TODO: drone state should be related to motor state, but now we are taking a shortcuff and make it directly associated with the gcs command. It should be that gcs command -> controllor -> motor
% However, the relationship between drone state and motor state will be impossible to be expressed by ASP comprehensively.
% We can use ASP to describe simple drone state transitions (e.g., motor turns to zero while throttle remains positive), but that's not complete.
% To this end, we have to either use enumeration to get simple ASP-expressible rules (e.g., motor turns to 1 while throttle > 0)
% or we have to have complicated constraints that can be verified by programs or SMT.
state_drone_takeoff(T+1) :- action_gcs_settakeoff(T). 
state_drone_land(T+1) :- action_gcs_setland(T). 
state_drone_poweroff(T+1) :- state_drone_land(T), action_gcs_setdisarm(T).

drone_crash(T+1) :- state_drone_takeoff(T), state_motor(T, 0), time(T), T+1 <= 10.

state_drone_takeoff(T+1) :- state_drone_takeoff(T), not state_motor(T, 0), time(T).

drone_crash(T+1) :- drone_crash(T), time(T), T+1 <= 10.


%%%%%%%%%%%%%% Motor state %%%%%%%%%%
% TODO: need to define controller state. The definition should be different over different layers, and the CPSV will be described based on one layer.

state_motor(T+1, Speed) :- output_controller_setmotorvalue(T, Speed), time(T). 


% GCS set the desired position of the drone (e.g., go left for 5m), and the controller decide the value of the motor (e.g., yaw, spin, pitch, throttle value) 
% what's the value to be set for the motor?
% We cannot express how the algorithm works via SMT or ASP.
% If we want to use ASP to verify the attack, then this value will be calculated in python, and then being passed to this rule (X).
% If we only want to hypothesize a CPV, which is to find what CPSVs can be chained together, then we just overapproximate it, e.g., say that we can set motor to any value.

% output_controller_setmotorvalue(T+1, Y) : speed(Y) :- action_gcs_setvalue(T, X), speed(X).
output_controller_setmotorvalue(T+1, Y) :- action_gcs_setvalue(T, X), speed(X), X != 100, Y = X.

% Ultimate goal
#maximize{ 1, T: drone_crash(T) }.
#minimize{ 1, T : attack_cpsv_mavlink(T) }.
#minimize{ 1, T : attack_cpsv_overflow(T) }.

