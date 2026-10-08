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
///
/// Transitions: `Running ⇄ Paused`, and either may go to `Stopped`. `Stopped`
/// is terminal — a stopped node is restarted by launching the daemon again,
/// not by a transition here. `pause`/`resume` are idempotent within their
/// state.
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

    /// Pause the local node (stop accepting new sessions; existing ones drain).
    /// Idempotent when already paused; rejected once stopped.
    pub fn pause(&mut self) -> Result<NodeState, ComplianceError> {
        match self.state {
            NodeState::Running | NodeState::Paused => {
                self.state = NodeState::Paused;
                Ok(self.state)
            }
            NodeState::Stopped => Err(ComplianceError::InvalidTransition("cannot pause a stopped node")),
        }
    }

    /// Resume a paused node. Idempotent when already running; rejected once stopped.
    pub fn resume(&mut self) -> Result<NodeState, ComplianceError> {
        match self.state {
            NodeState::Running | NodeState::Paused => {
                self.state = NodeState::Running;
                Ok(self.state)
            }
            NodeState::Stopped => Err(ComplianceError::InvalidTransition("cannot resume a stopped node")),
        }
    }

    /// Stop the local node. Terminal.
    pub fn stop(&mut self) -> Result<NodeState, ComplianceError> {
        self.state = NodeState::Stopped;
        Ok(self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pause_resume_cycle() {
        let mut c = LocalNodeControl::default();
        assert_eq!(c.state(), NodeState::Running);
        assert_eq!(c.pause().unwrap(), NodeState::Paused);
        assert_eq!(c.pause().unwrap(), NodeState::Paused); // idempotent
        assert_eq!(c.resume().unwrap(), NodeState::Running);
    }

    #[test]
    fn stop_is_terminal() {
        let mut c = LocalNodeControl::default();
        assert_eq!(c.stop().unwrap(), NodeState::Stopped);
        assert!(c.pause().is_err());
        assert!(c.resume().is_err());
    }
}
