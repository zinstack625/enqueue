use serde::{Serialize, Deserialize};

#[derive(Deserialize, Debug)]
pub struct EnqueueRequest {
    pub name: String,
    pub group: String,
}

#[derive(Serialize, Debug)]
pub struct EnqueueResponse {
    pub status: String,
    pub comment: String,
    pub id: i32,
    pub challenge: String,
}

#[derive(Deserialize, Debug)]
pub struct LoginRequest {
    pub name: String,
    pub group: String,
}

#[derive(Serialize, Debug)]
pub struct LoginResponse {
    pub secret: String,
}

#[derive(Serialize, Debug)]
pub struct LoginChallenge {
    pub salt1: String,
    pub salt2: String,
    pub iterations: i32,
}

#[derive(Serialize, Debug)]
pub struct QueueModel {
    pub position: i32,
    pub id: i32,
    pub name: String,
    pub group: String,
}
