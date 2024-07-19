use std::time::Duration;

use btleplug::api::{Central, Manager as _, ScanFilter};

use btleplug::platform::{Adapter, Manager, Peripheral};
use tokio::time;
use uuid::Uuid;

const BLUEAIR_CHARACTERISTIC: &str = "4772911e-d07c-4617-8241-f4d10948d6ae";

pub struct Discovery {
  adapter: Adapter,
}

impl Discovery {
  pub async fn new() -> Self {
    let manager = Manager::new().await.unwrap();
    let central = manager.adapters().await.unwrap().pop().unwrap();

    Discovery { adapter: central }
  }

  pub async fn discover_devices(&self, timeout: u64) -> Result<Vec<Peripheral>, btleplug::Error> {
    let filter = ScanFilter {
      services: vec![Uuid::parse_str(BLUEAIR_CHARACTERISTIC).unwrap()],
    };

    // Discover devices for 10 seconds
    self.adapter.start_scan(filter).await?;
    time::sleep(Duration::from_secs(timeout)).await;
    self.adapter.stop_scan().await?;

    let peripherals = self.adapter.peripherals().await?;

    Ok(peripherals)
  }
}
