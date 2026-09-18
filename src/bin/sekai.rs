fn main() -> Result<(), Box<dyn std::error::Error>> {
    sekai_chisei::control_plane::run(sekai_chisei::plane::ProcessPlane::Sekai)
}
