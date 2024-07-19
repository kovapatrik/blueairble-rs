use blueairble_rs::{
  discovery::Discovery,
  service::{Configuration, Service},
};
use btleplug::api::Peripheral;

#[tokio::main]
async fn main() {
  let ble = Discovery::new().await;
  let devices = ble.discover_devices(3).await.unwrap();

  for device in devices.clone() {
    let props = device.properties().await.unwrap().unwrap();
    println!("Device: {:?}", props);
  }

  let first_device = devices.first().unwrap();

  let mut service = Service::new(first_device.clone());

  service.connect().await.unwrap();

  let config = Configuration {
    api_url: "http://192.168.0.4:8080".to_string(),
    auth_url: "http://192.168.0.4:8081".to_string(),
    broker_url: "http://192.168.0.10:1883".to_string(),
    region: "eu-west-1".to_string(),
    random_text: "random".to_string(),
    secure_random: "secure_random".to_string(),
  };

  service.set_configuration(config).await.unwrap();
  service.wifi_connect(std::env::var("BLUEAIR_WIFI_SSID").unwrap().as_str(), std::env::var("BLUEAIR_WIFI_PASS").unwrap().as_str()).await.unwrap();

  let events = service.get_all_event().await.unwrap();
  for event in events {
    println!("Event: {:?}", event);
  }
}
