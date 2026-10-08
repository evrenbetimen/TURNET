//! Local, operator-controlled node pause/shutdown. **Stub.**
//!
//! # Scope is deliberately local
//! This primitive lets the operator of a node pause or stop **their own**
//! node — the machine they administer. That is an ordinary operational
//! control (maintenance, responding to abuse of their own service, complying
//! with an order directed at them).
//!
//! The original specification called for a genesis-private-key signal that
//! could **freeze whole network regions** remotely. That capability has been
//! **intentionally omitted** from this crate: a remote, region-scale freeze
//! triggered by an external signal is censorship / kill-switch
//! infrastructure, not operator compliance tooling, and it is exactly the
//! kind of mechanism a 100-year resilient network should be resistant to —
//! not ship with. Re-introducing anything broader than local control must be
//! a separate, deliberately-reviewed design decision, not an extension of
//! this stub.

use crate::ComplianceError;

/// The run state of the local node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    /// Accepting and relaying traffic.
    Running,
    /// Temporarily not accepting new sessions (existing ones may drain).
    Paused,
    /// Stopped.
    Stopped,
}

/// Controls the local node's run state. Scope: this node only.
pub struct LocalNodeControl {
    state: NodeState,
}

impl Default for LocalNodeControl {
    fn default() -> Self {
        Self { state: NodeState::Running }
    }
}

impl LocalNodeControl {
    /// Current state.
    pub fn state(&self) -> NodeState {
        self.state
    }

    /// Pause the local node.
    ///
    /// Stub: records intent only; draining/teardown is wired to the relay
    /// engine in a later milestone.
    pub fn pause(&mut self) -> Result<(), ComplianceError> {
        self.state = NodeState::Paused;
        Err(ComplianceError::NotImplemented("local node pause drain"))
    }

    /// Stop the local node.
    pub fn stop(&mut self) -> Result<(), ComplianceError> {
        self.state = NodeState::Stopped;
        Err(ComplianceError::NotImplemented("local node stop"))
    }
}
