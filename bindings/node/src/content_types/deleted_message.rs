use napi_derive::napi;
use xmtp_mls::DeletedBy as XmtpDeletedBy;

#[napi(string_enum)]
#[derive(Clone, PartialEq)]
pub enum DeletedBy {
  Sender,
  Admin,
}

#[napi(object)]
#[derive(Clone)]
pub struct DeletedMessage {
  pub deleted_by: DeletedBy,
  pub admin_inbox_id: Option<String>,
}

impl From<XmtpDeletedBy> for DeletedBy {
  fn from(value: XmtpDeletedBy) -> Self {
    match value {
      XmtpDeletedBy::Sender => DeletedBy::Sender,
      XmtpDeletedBy::Admin(_) => DeletedBy::Admin,
    }
  }
}

impl From<XmtpDeletedBy> for DeletedMessage {
  fn from(value: XmtpDeletedBy) -> Self {
    match value {
      XmtpDeletedBy::Sender => DeletedMessage {
        deleted_by: DeletedBy::Sender,
        admin_inbox_id: None,
      },
      XmtpDeletedBy::Admin(inbox_id) => DeletedMessage {
        deleted_by: DeletedBy::Admin,
        admin_inbox_id: Some(inbox_id),
      },
    }
  }
}
