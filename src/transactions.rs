//! transactions
//!
//! transaction builds used by state entity


/// transaction builders
pub trait Transactions {
   /// build funding transaction
   fn buildFundingTx() -> String;
   /// build kick-off transaction
   fn buildKickOffTx() -> String;
   /// build refund transaction
   fn buildRefundfTx() -> String;
}
