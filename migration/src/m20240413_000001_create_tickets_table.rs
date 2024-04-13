use sea_orm_migration::prelude::*;

use super::m20240413_000001_create_users_table::Users;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20240413_000001_create_tickets_table"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Tickets::Table)
                    .col(
                        ColumnDef::new(Tickets::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Tickets::UserId)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Tickets::InQueue)
                            .boolean()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Tickets::Table, Tickets::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade)
                    )
                    .to_owned(),
            )
            .await
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(Tickets::Table).to_owned()).await
    }
}

#[derive(Iden)]
pub enum Tickets {
    Table,
    Id,
    UserId,
    InQueue,
}
