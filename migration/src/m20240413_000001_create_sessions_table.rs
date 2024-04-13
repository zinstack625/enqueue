use sea_orm_migration::prelude::*;

use crate::m20240413_000001_create_users_table::Users;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20240413_000001_create_sessions_table"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Sessions::Table)
                    .col(
                        ColumnDef::new(Sessions::UserId)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Sessions::SessionToken)
                            .blob(BlobSize::Tiny)
                            .unique_key()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Sessions::Expiration)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Sessions::Table, Sessions::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade)
                    )
                    .to_owned(),
            )
            .await
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(Sessions::Table).to_owned()).await
    }
}

#[derive(Iden)]
pub enum Sessions {
    Table,
    UserId,
    SessionToken,
    Expiration,
}
