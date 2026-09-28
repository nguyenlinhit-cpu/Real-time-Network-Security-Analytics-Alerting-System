use crate::error::AppError;
use common::models::{Alert, ChannelType};
use std::future::Future;
use std::pin::Pin;

pub trait NotificationChannel: Send + Sync {
    fn name(&self) -> &str;
    fn channel_type(&self) -> ChannelType;
    fn send<'a>(
        &'a self,
        alert: &'a Alert,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + 'a>>;
}
