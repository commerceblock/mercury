use rocket::http::Status;
pub use crate::{error::SEError, Result};
use rocket::State;
use cfg_if::cfg_if;
use crate::server::StateChainEntity;

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
pub fn ping() -> Status {
    // TODO: Add logic for health check
    Status::Ok
}

#[get("/ping/rate_limited")]
pub fn ping_rate_limited(sc_entity: State<SCE>) -> Result<Status> {
    sc_entity.ping_rate_limited()?;
    Ok(Status::Ok)
}

pub trait Ping {
    fn ping_rate_limited(&self) -> Result<()>;
}

impl Ping for SCE {
    fn ping_rate_limited(&self) -> Result<()> {
        self.rate_limiter.check_key(&String::from("ping"))?;
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use super::super::util::tests::test_sc_entity;
    use std::{thread, time::Duration};

    #[test]
    fn test_ping_rate_limited() {
        let mut db = MockDatabase::new();
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        //db.expect_create_user_session().returning(|_, _, _, _| Ok(()));
        
        let sc_entity = test_sc_entity(db, None);
        assert_eq!(sc_entity.ping_rate_limited().unwrap(), ());
        match sc_entity.ping_rate_limited() {
            Err(SEError::RateLimitError(ref message)) => {
                ()
            },
            _ => assert!(false, "expected RateLimitError")
        }

        thread::sleep(Duration::from_millis(1000u64 / (sc_entity.config.rate_limit.get() as u64) + 1u64));
        assert_eq!(sc_entity.ping_rate_limited().unwrap(), ());
    }
}