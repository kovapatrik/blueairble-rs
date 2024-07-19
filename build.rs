use std::io::Result;

fn main() -> Result<()> {
  protobuf_codegen::Codegen::new()
    .protoc()
    .includes(&["src/protos"])
    .input("src/protos/constants.proto")
    .input("src/protos/custom_commands.proto")
    .input("src/protos/sec0.proto")
    .input("src/protos/sec1.proto")
    .input("src/protos/session.proto")
    .input("src/protos/wifi_config.proto")
    .input("src/protos/wifi_constants.proto")
    .input("src/protos/wifi_scan.proto")
    .cargo_out_dir("protos")
    .run()
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
  Ok(())
}
