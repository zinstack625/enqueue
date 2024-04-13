use sea_orm_migration::prelude::*;

use super::m20240413_000001_create_groups_table::Groups;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20240413_000001_create_users_table"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .col(
                        ColumnDef::new(Users::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Users::Name)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Users::GroupId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Users::ChallengeHash)
                            .blob(BlobSize::Tiny)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Users::ChallengeSalt)
                            .blob(BlobSize::Tiny)
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Users::Table, Users::GroupId)
                            .to(Groups::Table, Groups::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade)
                    )
                    .to_owned(),
            )
            .await
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(Users::Table).to_owned()).await
    }
}

#[derive(Iden)]
pub enum Users {
    Table,
    Id,
    Name,
    GroupId,
    ChallengeHash,
    ChallengeSalt,
}
