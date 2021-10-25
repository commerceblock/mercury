use rocket::http::Status;
pub use crate::{error::SEError, Result};
use rocket::State;
use cfg_if::cfg_if;
use crate::server::StateChainEntity;
use crate::protocol::util::RateLimiter;

//Generics cannot be used in Rocket State, therefore we define the concrete
//type of StateChainEntity here
cfg_if! {
    if #[cfg(any(test,feature="mockdb"))]{
        use crate::MockDatabase;
        use monotree::database::MemoryDB;
        type SCE = StateChainEntity::<MockDatabase, MemoryDB>;
    } else {
        use crate::PGDatabase;
        type SCE = StateChainEntity::<PGDatabase, PGDatabase>;
    }
}

#[get("/ping")]
pub fn ping(sc_entity: State<SCE>) -> Result<Status> {
    // TODO: Add logic for health check
    sc_entity.ping()?;
    Ok(Status::Ok)
}

pub trait Ping {
    fn ping(&self) -> Result<()>;
}

impl Ping for SCE {
    fn ping(&self) -> Result<()> {
        self.check_rate_fast("info")?;
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use super::super::util::tests::test_sc_entity;
    use std::{thread, time::Duration};
    use std::num::NonZeroU32;

    #[test]
    fn test_ping() {
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        //db.expect_create_user_session().returning(|_, _, _, _| Ok(()));
        
        let rate_limit = NonZeroU32::new(1);

        let sc_entity = test_sc_entity(db, None, rate_limit, rate_limit, rate_limit);
        assert_eq!(sc_entity.ping().unwrap(), ());
        match sc_entity.ping() {
            Err(SEError::RateLimitError(ref _message)) => {
                ()
            },
            _ => assert!(false, "expected RateLimitError")
        }

        thread::sleep(Duration::from_millis(1000u64 / (rate_limit.unwrap().get() as u64) + 1u64));
        assert_eq!(sc_entity.ping().unwrap(), ());
    }
}