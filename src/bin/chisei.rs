fn main() -> Result<(), Box<dyn std::error::Error>> {
    sekai_chisei::server::boot(sekai_chisei::grpc::ServicePlane::Chisei)
}
