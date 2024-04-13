pub use sea_orm_migration::prelude::*;

mod m20240413_000001_create_groups_table;
mod m20240413_000001_create_users_table;
mod m20240413_000001_create_tickets_table;
mod m20240413_000001_create_sessions_table;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20240413_000001_create_groups_table::Migration),
            Box::new(m20240413_000001_create_users_table::Migration),
            Box::new(m20240413_000001_create_tickets_table::Migration),
            Box::new(m20240413_000001_create_sessions_table::Migration),
        ]
    }
}
