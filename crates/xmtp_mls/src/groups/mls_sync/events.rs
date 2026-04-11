use super::*;
use crate::messages::decoded_message::DecodedMessage;
use std::collections::VecDeque;
use tokio::sync::broadcast;

pub(crate) trait DeferredEventContext {
    fn worker_events(&self) -> &broadcast::Sender<SyncWorkerEvent>;
    fn local_events(&self) -> &broadcast::Sender<LocalEvents>;
}

impl<Context> DeferredEventContext for Context
where
    Context: XmtpSharedContext,
{
    fn worker_events(&self) -> &broadcast::Sender<SyncWorkerEvent> {
        XmtpSharedContext::worker_events(self)
    }

    fn local_events(&self) -> &broadcast::Sender<LocalEvents> {
        XmtpSharedContext::local_events(self)
    }
}

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
    pub fn send_all<Context: DeferredEventContext>(&mut self, context: &Context) {
        while let Some(event) = self.worker_events.pop_front() {
            let _ = context.worker_events().send(event);
        }

        while let Some(event) = self.local_events.pop_front() {
            let _ = context.local_events().send(event);
        }
    }
}

pub(super) fn emit_local_event<Context>(context: &Context, event: LocalEvents)
where
    Context: DeferredEventContext,
{
    let _ = context.local_events().send(event);
}

pub(super) fn emit_message_deleted_event<Context>(
    context: &Context,
    decoded_message: DecodedMessage,
) where
    Context: DeferredEventContext,
{
    emit_local_event(
        context,
        LocalEvents::MessageDeleted(Box::new(decoded_message)),
    );
}
