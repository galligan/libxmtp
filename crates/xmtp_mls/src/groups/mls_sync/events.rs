use super::*;
use std::collections::VecDeque;

/// Collects events that should be sent after database transactions complete
#[derive(Default)]
pub(crate) struct DeferredEvents {
    worker_events: VecDeque<SyncWorkerEvent>,
    local_events: VecDeque<LocalEvents>,
}

impl DeferredEvents {
    pub fn new() -> Self {
        Self {
            worker_events: VecDeque::new(),
            local_events: VecDeque::new(),
        }
    }

    pub fn add_worker_event(&mut self, event: SyncWorkerEvent) {
        self.worker_events.push_back(event);
    }

    #[allow(dead_code)]
    pub fn add_local_event(&mut self, event: LocalEvents) {
        self.local_events.push_back(event);
    }

    /// Send all collected events to their respective channels
    pub fn send_all<Context: XmtpSharedContext>(&mut self, context: &Context) {
        while let Some(event) = self.worker_events.pop_front() {
            let _ = context.worker_events().send(event);
        }

        while let Some(event) = self.local_events.pop_front() {
            let _ = context.local_events().send(event);
        }
    }
}
