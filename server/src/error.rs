//! # Error
//!
//! Custom Error types for server

use shared_lib::error::SharedLibError;

use crate::storage::db::Column;
use bitcoin::secp256k1::Error as SecpError;
use config_rs::ConfigError;
use monotree::Errors as MonotreeErrors;
use postgres::Error as PostgresError;
use rocket::http::{ContentType, Status};
use rocket::response::Responder;
use rocket::{Request, Response};
use std::error;
use std::fmt;
use std::io::Cursor;
use std::time::SystemTimeError;

/// State Entity library specific errors
#[derive(Debug, Deserialize)]
pub enum SEError {
    /// Generic error from string error message
    Generic(String),
    /// Athorisation failed
    AuthError,
    /// Error in co-signing
    SigningError(String),
    /// DB error no ID found
    DBError(DBErrorType, String),
    /// DB error no data in column for ID
    DBErrorWC(DBErrorType, String, Column),
    /// Inherit errors from Util
    SharedLibError(String),
    /// Inherit errors from Monotree
    SMTError(String),
    /// Swap error
    SwapError(String),
    /// Try again error
    TryAgain(String),
    /// Batch transfer timeout
    TransferBatchEnded(String)
}

impl From<String> for SEError {
    fn from(e: String) -> SEError {
        SEError::Generic(e)
    }
}
impl From<SharedLibError> for SEError {
    fn from(e: SharedLibError) -> SEError {
        SEError::SharedLibError(e.to_string())
    }
}
impl From<MonotreeErrors> for SEError {
    fn from(e: MonotreeErrors) -> SEError {
        SEError::SMTError(e.to_string())
    }
}
impl From<SecpError> for SEError {
    fn from(e: SecpError) -> SEError {
        SEError::SigningError(e.to_string())
    }
}
impl From<SystemTimeError> for SEError {
    fn from(e: SystemTimeError) -> SEError {
        SEError::Generic(e.to_string())
    }
}
impl From<PostgresError> for SEError {
    fn from(e: PostgresError) -> SEError {
        SEError::Generic(e.to_string())
    }
}
impl From<ConfigError> for SEError {
    fn from(e: ConfigError) -> SEError {
        SEError::Generic(e.to_string())
    }
}

impl From<std::sync::PoisonError<std::sync::MutexGuard<'_, crate::protocol::conductor::Scheduler>>>
    for SEError
{
    fn from(
        e: std::sync::PoisonError<std::sync::MutexGuard<'_, crate::protocol::conductor::Scheduler>>,
    ) -> SEError {
        SEError::Generic(e.to_string())
    }
}

/// DB error types
#[derive(Debug, Deserialize)]
pub enum DBErrorType {
    /// No identifier
    NoDataForID,
    /// No update made
    UpdateFailed,
    // Connection to db failed
    ConnectionFailed,
}
impl DBErrorType {
    fn as_str(&self) -> &'static str {
        match *self {
            DBErrorType::NoDataForID => "No data for identifier.",
            DBErrorType::UpdateFailed => "No update made.",
            DBErrorType::ConnectionFailed => "Connection failed.",
        }
    }
}

impl fmt::Display for SEError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SEError::Generic(ref e) => write!(f, "Error: {}", e),
            SEError::AuthError => write!(f, "Authentication Error: User authorisation failed"),
            SEError::DBError(ref e, ref id) => write!(f, "DB Error: {} (id: {})", e.as_str(), id),
            SEError::DBErrorWC(ref e, ref id, ref col) => write!(
                f,
                "DB Error: {} (id: {} col: {})",
                e.as_str(),
                id,
                col.to_string()
            ),
            SEError::SigningError(ref e) => write!(f, "Signing Error: {}", e),
            SEError::SharedLibError(ref e) => write!(f, "SharedLibError Error: {}", e),
            SEError::SMTError(ref e) => write!(f, "SMT Error: {}", e),
            SEError::SwapError(ref e) => write!(f, "Swap Error: {}", e),
            SEError::TryAgain(ref e) => write!(f, "Error: try again: {}", e),
            SEError::TransferBatchEnded(ref e) => write!(f, "Error: Transfer batch ended. {}", e),
        }
    }
}

impl error::Error for SEError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            _ => None,
        }
    }
}

impl Responder<'static> for SEError {
    fn respond_to(self, _: &Request) -> ::std::result::Result<Response<'static>, Status> {
        Response::build()
            .header(ContentType::JSON)
            .sized_body(Cursor::new(format!("{}", self)))
            .ok()
    }
}
