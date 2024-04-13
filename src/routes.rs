use std::{sync::Arc, future::Future, pin::Pin};

use base64::Engine;
use bytes::Bytes;
use hyper::{service::Service, Request, body::{Incoming, Body}, Response, Method};
use http_body_util::{Full, BodyExt};
use rand::{SeedableRng, Rng};
use sea_orm::{EntityTrait, QueryFilter, ColumnTrait, ActiveValue, QueryOrder, ActiveModelTrait};
use sha3::{Digest, Sha3_256};

use crate::{models::http_requests, entities::{self, users, groups, tickets, sessions}};
use entities::prelude::*;

#[derive(Debug, Clone)]
pub struct Svc {
    db: Arc<sea_orm::DatabaseConnection>,
}

impl Svc {
    pub async fn new(dbdsn: &str) -> Result<Self, sea_orm::DbErr> {
        let db = sea_orm::Database::connect(dbdsn).await?;
        db.ping().await?;
        Ok(Self {
            db: Arc::new(db)
        })
    }
    async fn check_out(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let Some(token) = req.headers().get("Auth") else {
            return Ok(Response::builder()
                .status(hyper::StatusCode::UNAUTHORIZED)
                .body(Full::new(Bytes::from_static(b""))).unwrap());
        };
        let b64 = base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD, base64::engine::GeneralPurposeConfig::new());
        let Ok(token) = b64.decode(token) else {
            return Ok(Response::builder()
                .status(hyper::StatusCode::UNAUTHORIZED)
                .body(Full::new(Bytes::from_static(b""))).unwrap());
        };
        let Ok(Some((session, Some(user)))) = Sessions::find()
            .filter(sessions::Column::SessionToken.eq(token))
            .filter(sessions::Column::Expiration.gt(chrono::Utc::now()))
            .find_also_related(Users)
            .one(self.db.as_ref()).await else {
                return self.report_error().await;
            };
        Tickets::delete_many()
            .filter(tickets::Column::UserId.eq(user.id))
            .exec(self.db.as_ref()).await;
        return Ok(Response::builder()
                .status(hyper::StatusCode::OK)
                .body(Full::new(Bytes::from_static(b""))).unwrap());
    }
    async fn get_challenge(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let bytes = req.collect().await?.to_bytes();
        let Ok(request) = serde_json::from_slice::<http_requests::LoginRequest>(&bytes) else {
            return Ok(Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from_static(b"Invalid structure"))).unwrap());
        };
        let user = Users::find()
            .filter(users::Column::Name.eq(&request.name))
            .filter(users::Column::GroupId.eq(&request.group))
            .one(self.db.as_ref())
            .await;
        if user.is_err() {
            return self.report_error().await;
        }
        if user.as_ref().unwrap().is_none() {
            return Ok(Response::builder()
                .status(hyper::StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from_static(b"No such user"))).unwrap());
        }
        let user = user.unwrap().unwrap();
        let mut rng = rand::rngs::StdRng::from_entropy();
        let mut salt = vec![0u8; 4];
        rng.try_fill(salt.as_mut_slice());
        let b64 = base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD, base64::engine::GeneralPurposeConfig::new());
        let response = http_requests::LoginChallenge {
            salt1: b64.encode(user.challenge_salt),
            salt2: b64.encode(salt.clone()),
            iterations: rng.gen_range(10000..20000),
        };
        let mut hash = user.challenge_hash;
        for i in 1..response.iterations {
            let mut to_store = Sha3_256::new_with_prefix(&salt);
            to_store.update(&hash);
            hash = Vec::from(to_store.finalize().as_slice());
        }
        let mut trash = hash.clone();
        for i in response.iterations..20000 {
            let mut to_store = Sha3_256::new_with_prefix(&salt);
            to_store.update(&trash);
            trash = Vec::from(to_store.finalize().as_slice());
        }
        let session_token = sessions::ActiveModel {
            user_id: ActiveValue::Set(user.id),
            session_token: ActiveValue::Set(hash),
            expiration: ActiveValue::Set(chrono::Utc::now().fixed_offset().checked_add_signed(chrono::TimeDelta::hours(1)).unwrap()),
        };
        Sessions::insert(session_token)
            .on_conflict(
                sea_query::OnConflict::column(sessions::Column::UserId)
                    .update_columns([sessions::Column::SessionToken, sessions::Column::Expiration])
                    .to_owned()
            )
            .exec(self.db.as_ref()).await;
        let body = Bytes::from(serde_json::to_vec(&response).unwrap());
        return Ok(Response::builder()
                .status(hyper::StatusCode::OK)
                .body(Full::new(body)).unwrap());
    }
    async fn get_queue(&self, _: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let Ok(users) = Tickets::find()
            .filter(tickets::Column::InQueue.eq(true))
            .find_also_related(Users)
            .order_by_asc(tickets::Column::Id)
            .all(self.db.as_ref()).await else {
                return self.report_error().await;
            };
        let response = users.into_iter().enumerate().map(|m| {
            let user = m.1.1.unwrap_or(users::Model { id: 0, name: "undefined".to_string(), group_id: "undefined".to_string(), challenge_hash: Vec::new(), challenge_salt: Vec::new() });
            http_requests::QueueModel {
                position: m.0 as i32,
                id: user.id,
                name: user.name,
                group: user.group_id,
            }
        }).collect::<Vec<http_requests::QueueModel>>();
        let body = Bytes::from(serde_json::to_vec(&response).unwrap());
        return Ok(Response::builder()
            .status(hyper::StatusCode::OK)
            .body(Full::new(body)).unwrap());
    }
    async fn enqueue(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let auth = req.headers().get("Auth").cloned();
        let bytes = req.collect().await?.to_bytes();
        let Ok(request) = serde_json::from_slice::<http_requests::EnqueueRequest>(&bytes) else {
            return Ok(Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from_static(b"Invalid structure"))).unwrap());
        };
        let user = Users::find()
            .filter(users::Column::Name.eq(&request.name))
            .filter(users::Column::GroupId.eq(&request.group))
            .one(self.db.as_ref())
            .await;
        let user = if user.is_err() || user.as_ref().unwrap().is_none() {
            let group = groups::ActiveModel {
                id: ActiveValue::Set(request.group.clone()),
            };
            Groups::insert(group).on_conflict(
                sea_query::OnConflict::column(groups::Column::Id)
                    .do_nothing()
                    .to_owned()
            ).exec(self.db.as_ref()).await;
            let mut rng = rand::rngs::StdRng::from_entropy();
            let mut secret = vec![0u8; 12];
            let mut salt = vec![0u8; 4];
            rng.try_fill(secret.as_mut_slice());
            rng.try_fill(salt.as_mut_slice());
            let mut to_store = Sha3_256::new_with_prefix(&salt);
            to_store.update(secret);
            let stored_hash: Vec<u8> = Vec::from(to_store.finalize().as_slice());
            
            let user = users::ActiveModel {
                id: sea_orm::ActiveValue::NotSet,
                name: ActiveValue::Set(request.name.clone()),
                group_id: ActiveValue::Set(request.group.clone()),
                challenge_hash: ActiveValue::Set(stored_hash),
                challenge_salt: ActiveValue::Set(salt),
            };
            let res = user.insert(self.db.as_ref()).await;
            if res.is_err() {
                return self.report_error().await;
            }
            res.unwrap()
        } else {
            let Some(token) = auth else {
                return Ok(Response::builder()
                    .status(hyper::StatusCode::UNAUTHORIZED)
                    .body(Full::new(Bytes::from_static(b""))).unwrap());
            };
            let b64 = base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD, base64::engine::GeneralPurposeConfig::new());
            let Ok(token) = b64.decode(token) else {
                return Ok(Response::builder()
                    .status(hyper::StatusCode::UNAUTHORIZED)
                    .body(Full::new(Bytes::from_static(b""))).unwrap());
            };
            let user = user.unwrap().unwrap();
            let Ok(session) = Sessions::find()
                .filter(sessions::Column::UserId.eq(user.id))
                .one(self.db.as_ref()).await else {
                    return self.report_error().await;
                };
            if session.is_none() || session.unwrap().session_token != token {
                return Ok(Response::builder()
                    .status(hyper::StatusCode::UNAUTHORIZED)
                    .body(Full::new(Bytes::from_static(b""))).unwrap());
            }
            user
        };
        let ticket = entities::tickets::ActiveModel {
            id: ActiveValue::NotSet,
            user_id: ActiveValue::Set(user.id),
            in_queue: ActiveValue::Set(true),
        };
        let res = Tickets::insert(ticket).exec(self.db.as_ref()).await;
        if res.is_err() {
            return self.report_error().await;
        }
        let b64 = base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD, base64::engine::GeneralPurposeConfig::new());
        let response = http_requests::EnqueueResponse {
            status: "Added!".to_string(),
            comment: format!("{} successfully added to the queue", &request.name),
            id: res.unwrap().last_insert_id,
            challenge: b64.encode(user.challenge_hash)
        };
        let body = Bytes::from(serde_json::to_vec(&response).unwrap());
        return Ok(Response::builder()
                .status(hyper::StatusCode::OK)
                .body(Full::new(body)).unwrap());
    }
    async fn invalid(&self, _: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
        Ok(Response::builder()
            .header("Content-Type", "application/json")
            .status(hyper::StatusCode::METHOD_NOT_ALLOWED)
            .body(Full::new(Bytes::from_static(b"hello"))).unwrap())
    }
    async fn report_error(&self) -> Result<Response<Full<Bytes>>, hyper::Error> {
        return Ok(Response::builder()
            .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
            .body(Full::new(Bytes::from_static(b""))).unwrap());
    }
}

impl Service<Request<Incoming>> for Svc {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        if req.method() == Method::POST {
            let upper = req.body().size_hint().upper().unwrap_or(u64::MAX);
            if upper > 1024 * 64 {
                return Box::pin(async move {
                    Ok(Response::builder()
                        .status(hyper::StatusCode::PAYLOAD_TOO_LARGE)
                        .body(Full::new(Bytes::from_static(b"Body too large. Max 64K"))).unwrap())
                });
        }
        }
        let self_clone = self.clone();
        let res = async move {
            match (req.method(), req.uri().path()) {
                (&Method::POST, "/api/v1/queue") => self_clone.enqueue(req).await,
                (&Method::GET, "/api/v1/queue") => self_clone.get_queue(req).await,
                (&Method::DELETE, "/api/v1/queue") => self_clone.check_out(req).await,
                (&Method::POST, "/api/v1/challenge") => self_clone.get_challenge(req).await,
                _ => self_clone.invalid(req).await,
            }
        };
        Box::pin(res)
    }
}
