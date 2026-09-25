------------------------------ MODULE Clumps ------------------------------
(*
    Abstract security-state model for Clumps.

    This specification intentionally does NOT model Linux syscalls,
    seccomp-BPF instructions, or Landlock ABI details.

    Instead, it describes the security semantics Clumps is intended to
    provide at the policy/state-machine level:

      - pledge policy is monotonic (permissions may only be removed)
      - unveil permissions are monotonic (permissions may only be removed)
      - unveil locking is irreversible
      - a failed policy installation does not change enforced policy
      - exec pledge state is derived from successfully installed state
      - a child may contract its parent's policy, but may not expand it

    This is an abstract model, intended to expose semantic ambiguities and
    provide invariants against which the implementation can eventually be
    reasoned about.

    The model intentionally uses small finite sets so TLC can exhaustively
    explore bounded state spaces.
*)

EXTENDS Naturals, FiniteSets

CONSTANTS
    Promises,
    Paths,
    Permissions

ASSUME
    Promises # {} /\ Paths # {} /\ Permissions # {}

----------------------------------------------------------------------------
-- Basic policy operations
----------------------------------------------------------------------------

(*
    A policy is represented as a subset of the available promises.

    "More restrictive" means "contains no more permissions".
*)
MoreRestrictivePledge(new, old) ==
    new \subseteq old

(*
    Unveil permissions for a path are represented as a subset of the
    available permissions.
*)
MoreRestrictiveUnveil(new, old) ==
    new \subseteq old

(*
    Applying an unveil rule to an existing rule is intersection.

    This models the intended monotonic behavior: repeated rules cannot
    grant permissions that were previously removed.
*)
ApplyUnveil(existing, requested) ==
    existing \cap requested

----------------------------------------------------------------------------
-- Variables
----------------------------------------------------------------------------

VARIABLES
    pledgePolicy,
    enforcedPledge,
    execPledge,

    unveilPolicy,
    enforcedUnveil,

    unveilLocked,

    pledgeInstallationPending,
    pledgeInstallationSucceeded,

    execPledged,

    parentPolicy,
    childPolicy

vars ==
    << pledgePolicy,
       enforcedPledge,
       execPledge,
       unveilPolicy,
       enforcedUnveil,
       unveilLocked,
       pledgeInstallationPending,
       pledgeInstallationSucceeded,
       execPledged,
       parentPolicy,
       childPolicy >>

----------------------------------------------------------------------------
-- Initial state
----------------------------------------------------------------------------

Init ==
    /\ pledgePolicy = Promises
    /\ enforcedPledge = Promises
    /\ execPledge = Promises

    /\ unveilPolicy = [p \in Paths |-> Permissions]
    /\ enforcedUnveil = [p \in Paths |-> Permissions]

    /\ unveilLocked = FALSE

    /\ pledgeInstallationPending = FALSE
    /\ pledgeInstallationSucceeded = TRUE

    /\ execPledged = FALSE

    /\ parentPolicy = Promises
    /\ childPolicy = Promises

----------------------------------------------------------------------------
-- Pledge transitions
----------------------------------------------------------------------------

(*
    A successful pledge operation contracts the currently enforced policy.

    The abstract model assumes that a requested pledge can only remove
    permissions.
*)
Pledge(newPolicy) ==
    /\ newPolicy \subseteq enforcedPledge
    /\ pledgePolicy' = newPolicy
    /\ enforcedPledge' = newPolicy

    /\ UNCHANGED <<
        execPledge,
        unveilPolicy,
        enforcedUnveil,
        unveilLocked,
        pledgeInstallationPending,
        pledgeInstallationSucceeded,
        execPledged,
        parentPolicy,
        childPolicy
    >>

(*
    A failed pledge installation must leave the previously enforced policy
    authoritative.

    This captures an important implementation invariant: bookkeeping must
    not claim that a policy is installed when enforcement installation
    failed.
*)
PledgeFailure ==
    /\ pledgeInstallationPending = TRUE

    /\ pledgePolicy' = pledgePolicy
    /\ enforcedPledge' = enforcedPledge

    /\ pledgeInstallationPending' = FALSE
    /\ pledgeInstallationSucceeded' = FALSE

    /\ UNCHANGED <<
        execPledge,
        unveilPolicy,
        enforcedUnveil,
        unveilLocked,
        execPledged,
        parentPolicy,
        childPolicy
    >>

(*
    Successful installation commits the requested policy.
*)
PledgeSuccess ==
    /\ pledgeInstallationPending = TRUE
    /\ pledgePolicy \subseteq enforcedPledge

    /\ pledgePolicy' = pledgePolicy
    /\ enforcedPledge' = pledgePolicy

    /\ pledgeInstallationPending' = FALSE
    /\ pledgeInstallationSucceeded' = TRUE

    /\ UNCHANGED <<
        execPledge,
        unveilPolicy,
        enforcedUnveil,
        unveilLocked,
        execPledged,
        parentPolicy,
        childPolicy
    >>

----------------------------------------------------------------------------
-- Unveil transitions
----------------------------------------------------------------------------

(*
    Add or tighten an unveil rule.

    Once locked, unveil policy is immutable.
*)
Unveil(path, requestedPermissions) ==
    /\ path \in Paths
    /\ requestedPermissions \subseteq Permissions
    /\ ~unveilLocked

    /\ unveilPolicy' =
        [unveilPolicy EXCEPT
            ![path] =
                ApplyUnveil(@, requestedPermissions)]

    /\ enforcedUnveil' =
        [enforcedUnveil EXCEPT
            ![path] =
                ApplyUnveil(@, requestedPermissions)]

    /\ UNCHANGED <<
        pledgePolicy,
        enforcedPledge,
        execPledge,
        unveilLocked,
        pledgeInstallationPending,
        pledgeInstallationSucceeded,
        execPledged,
        parentPolicy,
        childPolicy
    >>

(*
    Locking unveil policy is irreversible.
*)
LockUnveil ==
    /\ ~unveilLocked

    /\ unveilLocked' = TRUE

    /\ UNCHANGED <<
        pledgePolicy,
        enforcedPledge,
        execPledge,
        unveilPolicy,
        enforcedUnveil,
        pledgeInstallationPending,
        pledgeInstallationSucceeded,
        execPledged,
        parentPolicy,
        childPolicy
    >>

----------------------------------------------------------------------------
-- Exec transitions
----------------------------------------------------------------------------

(*
    Save an exec pledge.

    The exec policy cannot expand the currently enforced pledge.
*)
SetExecPledge(newExecPolicy) ==
    /\ newExecPolicy \subseteq enforcedPledge

    /\ execPledge' = newExecPolicy

    /\ UNCHANGED <<
        pledgePolicy,
        enforcedPledge,
        unveilPolicy,
        enforcedUnveil,
        unveilLocked,
        pledgeInstallationPending,
        pledgeInstallationSucceeded,
        execPledged,
        parentPolicy,
        childPolicy
    >>

(*
    An exec transition installs the previously stored exec policy.

    The resulting policy is still a contraction of the policy currently
    enforced by the process.
*)
Exec ==
    /\ execPledge \subseteq enforcedPledge

    /\ enforcedPledge' = execPledge
    /\ execPledged' = TRUE

    /\ UNCHANGED <<
        pledgePolicy,
        execPledge,
        unveilPolicy,
        enforcedUnveil,
        unveilLocked,
        pledgeInstallationPending,
        pledgeInstallationSucceeded,
        parentPolicy,
        childPolicy
    >>

----------------------------------------------------------------------------
-- Process / child transitions
----------------------------------------------------------------------------

(*
    Fork inherits the parent's effective pledge policy.
*)
Fork ==
    /\ parentPolicy' = enforcedPledge
    /\ childPolicy' = enforcedPledge

    /\ UNCHANGED <<
        pledgePolicy,
        enforcedPledge,
        execPledge,
        unveilPolicy,
        enforcedUnveil,
        unveilLocked,
        pledgeInstallationPending,
        pledgeInstallationSucceeded,
        execPledged
    >>

(*
    A child may contract the inherited policy, but may never expand it.
*)
ChildContract(newPolicy) ==
    /\ newPolicy \subseteq childPolicy
    /\ childPolicy' = newPolicy

    /\ UNCHANGED <<
        pledgePolicy,
        enforcedPledge,
        execPledge,
        unveilPolicy,
        enforcedUnveil,
        unveilLocked,
        pledgeInstallationPending,
        pledgeInstallationSucceeded,
        execPledged,
        parentPolicy
    >>

----------------------------------------------------------------------------
-- Next-state relation
----------------------------------------------------------------------------

Next ==
    \/ \E newPolicy \in SUBSET Promises :
        Pledge(newPolicy)

    \/ PledgeFailure
    \/ PledgeSuccess

    \/ \E path \in Paths :
        \E permissions \in SUBSET Permissions :
            Unveil(path, permissions)

    \/ LockUnveil

    \/ \E newExecPolicy \in SUBSET Promises :
        SetExecPledge(newExecPolicy)

    \/ Exec

    \/ Fork

    \/ \E newPolicy \in SUBSET Promises :
        ChildContract(newPolicy)

----------------------------------------------------------------------------
-- Type invariant
----------------------------------------------------------------------------

TypeInvariant ==
    /\ enforcedPledge \subseteq Promises
    /\ execPledge \subseteq Promises
    /\ pledgePolicy \subseteq Promises
    /\ childPolicy \subseteq Promises
    /\ parentPolicy \subseteq Promises

    /\ \A p \in Paths :
        enforcedUnveil[p] \subseteq Permissions

    /\ \A p \in Paths :
        unveilPolicy[p] \subseteq Permissions

----------------------------------------------------------------------------
-- Security invariants
----------------------------------------------------------------------------

(*
    The enforced pledge can never contain anything outside the universe of
    available promises.
*)
PledgeNeverExpands ==
    enforcedPledge \subseteq Promises

(*
    Exec pledge may never contain promises absent from the currently
    enforced pledge.
*)
ExecNeverExpands ==
    execPledge \subseteq enforcedPledge

(*
    Every unveil rule contains only known permissions.
*)
UnveilPermissionsValid ==
    /\ \A p \in Paths :
        enforcedUnveil[p] \subseteq Permissions

    /\ \A p \in Paths :
        unveilPolicy[p] \subseteq Permissions

(*
    Once locked, the abstract unveil policies agree.
*)
LockIrreversible ==
    unveilLocked = TRUE =>
        unveilPolicy = enforcedUnveil

(*
    A successful installation means the recorded policy and enforced policy
    agree.
*)
SuccessfulInstallationConsistent ==
    pledgeInstallationSucceeded = TRUE =>
        pledgePolicy = enforcedPledge

(*
    A child policy cannot be broader than the policy inherited from its
    parent.
*)
ChildCannotExpand ==
    childPolicy \subseteq parentPolicy

(*
    Every child policy is itself a valid pledge policy.
*)
ChildPolicyValid ==
    childPolicy \subseteq Promises

----------------------------------------------------------------------------
-- Combined invariant
----------------------------------------------------------------------------

SecurityInvariant ==
    /\ PledgeNeverExpands
    /\ ExecNeverExpands
    /\ UnveilPermissionsValid
    /\ LockIrreversible
    /\ SuccessfulInstallationConsistent
    /\ ChildCannotExpand
    /\ ChildPolicyValid

----------------------------------------------------------------------------
-- Specification
----------------------------------------------------------------------------

Spec ==
    Init /\ [][Next]_vars

=============================================================================
