fn main() -> Result<(), Box<dyn std::error::Error>> {
    //    tonic_prost_build::compile_protos("../proto/spire.proto")?;
    tonic_prost_build::configure()
        .out_dir("src/generated")
        .compile_protos(&["../proto/spire.proto"], &["../proto"])?;
    Ok(())
}
