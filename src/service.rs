// Discovered characteristic: prov-scan, uuid: 4772ff50-d07c-4617-8241-f4d10948d6ae
// Discovered characteristic: prov-session, uuid: 4772ff51-d07c-4617-8241-f4d10948d6ae
// Discovered characteristic: prov-config, uuid: 4772ff52-d07c-4617-8241-f4d10948d6ae
// Discovered characteristic: proto-ver, uuid: 4772ff53-d07c-4617-8241-f4d10948d6ae
// Discovered characteristic: custom-endpoint, uuid: 4772ff54-d07c-4617-8241-f4d10948d6ae

use std::collections::HashMap;

use aes::cipher::{KeyIvInit, StreamCipher};
use btleplug::{
  api::{Characteristic, Peripheral as _, WriteType},
  platform::Peripheral,
  Result,
};
use bytes::Bytes;
use protobuf::{EnumOrUnknown, Message};
use serde_json::Number;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::protos::{self, wifi_constants::WifiAuthMode};
use std::time::{Duration, Instant};

type Aes256Ctr = ctr::Ctr32BE<aes::Aes256>;

const WIFI_PACKET_COUNT: u32 = 4;

enum BlueAirCharacteristic {
  ProvScan,
  ProvSession,
  ProvConfig,
  ProtoVer,
  CustomEndpoint,
}

impl BlueAirCharacteristic {
  fn as_str(&self) -> &'static str {
    match self {
      BlueAirCharacteristic::ProvScan => "prov-scan",
      BlueAirCharacteristic::ProvSession => "prov-session",
      BlueAirCharacteristic::ProvConfig => "prov-config",
      BlueAirCharacteristic::ProtoVer => "proto-ver",
      BlueAirCharacteristic::CustomEndpoint => "custom-endpoint",
    }
  }
}

#[derive(Debug)]
pub struct WiFiResult {
  ssid: String,
  bssid: String,
  channel: u32,
  rssi: i32,
  security: WifiAuthMode,
}

#[derive(Debug, Clone)]
pub struct Event {
  pub json: serde_json::Value,
  pub number_of_events: i32,
}

#[derive(Debug, Clone)]
pub struct Configuration {
  pub api_url: String,
  pub auth_url: String,
  pub broker_url: String,
  pub region: String,
  pub random_text: String,
  pub secure_random: String,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum ConfigurationEntry {
  ApiUrl,
  AuthUrl,
  BrokerUrl,
  Region,
  RandomText,
  SecureRandom,
}

impl Configuration {
  pub fn new(
    api_url: String,
    auth_url: String,
    broker_url: String,
    region: String,
    random_text: String,
    secure_random: String,
  ) -> Self {
    Self {
      api_url,
      auth_url,
      broker_url,
      region,
      random_text,
      secure_random,
    }
  }

  pub fn values(&self) -> HashMap<ConfigurationEntry, String> {
    let mut values = HashMap::new();
    values.insert(ConfigurationEntry::ApiUrl, self.api_url.clone());
    values.insert(ConfigurationEntry::AuthUrl, self.auth_url.clone());
    values.insert(ConfigurationEntry::BrokerUrl, self.broker_url.clone());
    values.insert(ConfigurationEntry::Region, self.region.clone());
    values.insert(ConfigurationEntry::RandomText, self.random_text.clone());
    values.insert(ConfigurationEntry::SecureRandom, self.secure_random.clone());
    values
  }
}

pub struct Service {
  peripheral: Peripheral,
  pub characteristics: HashMap<String, Characteristic>,
  cipher: Option<Aes256Ctr>,
  client_pubkey: Option<PublicKey>,
  device_pubkey: Option<PublicKey>,
  is_configured: bool,
}

impl Service {
  pub fn new(peripheral: Peripheral) -> Self {
    Self {
      peripheral,
      characteristics: HashMap::new(),
      cipher: None,
      client_pubkey: None,
      device_pubkey: None,
      is_configured: false,
    }
  }

  pub async fn connect(&mut self) -> Result<()> {
    self.peripheral.connect().await?;
    self.peripheral.discover_services().await?;

    for char in self.peripheral.characteristics() {
      let descriptor = char.descriptors.first().unwrap();
      let value = self.peripheral.read_descriptor(descriptor).await?;
      let char_name = String::from_utf8(value.clone()).unwrap();
      self.characteristics.insert(char_name, char);
    }

    // Setup session
    self.get_proto_ver().await?; // not neccessary to call
    self.step_session0().await?;
    self.step_session1().await?;
    self.step_start().await?;

    Ok(())
  }

  async fn get_proto_ver(&mut self) -> Result<Vec<u8>> {
    self
      .write_characteristic(BlueAirCharacteristic::ProtoVer, "ESP".as_bytes())
      .await?;
    let proto_ver_value = self
      .read_characteristic(BlueAirCharacteristic::ProtoVer)
      .await?;

    Ok(proto_ver_value)
  }

  pub async fn get_event(&mut self) -> Result<Event> {

    let mut custom_command_packet = protos::custom_commands::CommandWrapper::new();
    let mut payload = protos::custom_commands::EventCmd::new();
    payload.cmd = EnumOrUnknown::new(protos::custom_commands::EventCommands::EventGet);

    custom_command_packet.set_event_cmd(payload);

    let mut custom_command_packet = custom_command_packet.write_to_bytes().unwrap();
    self
      .cipher
      .as_mut()
      .unwrap()
      .apply_keystream(custom_command_packet.as_mut());

    self
      .write_characteristic(
        BlueAirCharacteristic::CustomEndpoint,
        custom_command_packet.as_slice(),
      )
      .await?;

    let mut read_value = self
      .read_characteristic(BlueAirCharacteristic::CustomEndpoint)
      .await?;

    self
      .cipher
      .as_mut()
      .unwrap()
      .apply_keystream(read_value.as_mut());

    let custom_command_response = protos::custom_commands::CommandWrapper::parse_from_bytes(&read_value).unwrap();
    let event_response = custom_command_response.event_resp();

    Ok(Event {
      json: serde_json::from_str(&event_response.json).unwrap_or(serde_json::Value::Null),
      number_of_events: event_response.number_of_events,
    })
  }

  pub async fn get_all_event(&mut self) -> Result<Vec<Event>> {
    let mut events = Vec::new();
    let mut event = self.get_event().await?;

    let mut number_of_events = event.number_of_events.clone();
    events.push(event);

    while number_of_events > 0 {
      event = self.get_event().await?;
      number_of_events = event.number_of_events.clone();
      events.push(event);
    }

    Ok(events)
  }

  async fn step_session0(&mut self) -> Result<()> {
    let mut session_packet = protos::session::SessionData::new();
    let secret_key = EphemeralSecret::random();
    let public_key = PublicKey::from(&secret_key);

    let mut payload = protos::sec1::Sec1Payload::new();
    payload.msg = EnumOrUnknown::new(protos::sec1::Sec1MsgType::Session_Command0);

    let mut session_command0 = protos::sec1::SessionCmd0::new();

    session_command0.client_pubkey = public_key.to_bytes().to_vec();
    payload.set_sc0(session_command0);

    session_packet.sec_ver = EnumOrUnknown::new(protos::session::SecSchemeVersion::SecScheme1);
    session_packet.set_sec1(payload);

    self
      .write_characteristic(
        BlueAirCharacteristic::ProvSession,
        session_packet.write_to_bytes().unwrap().as_slice(),
      )
      .await?;

    let read_value: Bytes = self
      .read_characteristic(BlueAirCharacteristic::ProvSession)
      .await?
      .into();

    let session_data = protos::session::SessionData::parse_from_bytes(&read_value).unwrap();

    let session_response = session_data.sec1().sr0();
    let status = session_response.status.enum_value().unwrap();

    if status != protos::constants::Status::Success {
      return Err(btleplug::Error::RuntimeError(format!(
        "Session response status: {:?}",
        status
      )));
    }

    let device_pubkey: [u8; 32] = session_response.device_pubkey.clone().try_into().unwrap();
    let device_random = session_response.device_random.as_slice();
    let device_pubkey = PublicKey::from(device_pubkey);
    let shared_secret = secret_key.diffie_hellman(&device_pubkey);

    self.cipher = Some(Aes256Ctr::new(
      shared_secret.as_bytes().into(),
      device_random.into(),
    ));

    self.client_pubkey = Some(public_key);
    self.device_pubkey = Some(device_pubkey);

    Ok(())
  }

  async fn step_session1(&mut self) -> Result<()> {
    if self.cipher.is_none() {
      return Err(btleplug::Error::RuntimeError(
        "Cipher not initialized".to_string(),
      ));
    }

    if self.device_pubkey.is_none() {
      return Err(btleplug::Error::RuntimeError(
        "Device pubkey not initialized".to_string(),
      ));
    }

    if self.client_pubkey.is_none() {
      return Err(btleplug::Error::RuntimeError(
        "Client pubkey not initialized".to_string(),
      ));
    }

    let device_public_key = self.device_pubkey.as_ref().unwrap();
    let client_public_key = self.client_pubkey.as_ref().unwrap();

    let mut buf = [0u8; 32];
    self
      .cipher
      .as_mut()
      .unwrap()
      .apply_keystream_b2b(device_public_key.as_bytes(), &mut buf)
      .unwrap();

    let mut session_packet = protos::session::SessionData::new();
    let mut payload = protos::sec1::Sec1Payload::new();
    let mut session_command1 = protos::sec1::SessionCmd1::new();

    session_command1.client_verify_data = buf.to_vec();

    payload.msg = EnumOrUnknown::new(protos::sec1::Sec1MsgType::Session_Command1);
    payload.set_sc1(session_command1);

    session_packet.sec_ver = EnumOrUnknown::new(protos::session::SecSchemeVersion::SecScheme1);
    session_packet.set_sec1(payload);

    self
      .write_characteristic(
        BlueAirCharacteristic::ProvSession,
        session_packet.write_to_bytes().unwrap().as_slice(),
      )
      .await?;

    let read_value: Bytes = self
      .read_characteristic(BlueAirCharacteristic::ProvSession)
      .await?
      .into();

    let session_response1 =
      protos::session::SessionData::parse_from_tokio_bytes(&read_value).unwrap();
    let session_response1 = session_response1.sec1().sr1();

    let status = session_response1.status.enum_value().unwrap();

    if status != protos::constants::Status::Success {
      return Err(btleplug::Error::RuntimeError(format!(
        "Session response 1 status: {:?}",
        status
      )));
    }

    let device_verify_data = session_response1.device_verify_data.as_slice();
    self
      .cipher
      .as_mut()
      .unwrap()
      .apply_keystream_b2b(device_verify_data, &mut buf)
      .unwrap();

    if client_public_key.as_bytes() != &buf {
      return Err(btleplug::Error::RuntimeError(
        "Invalid device verify data".to_string(),
      ));
    }

    Ok(())
  }

  async fn step_start(&mut self) -> Result<()> {
    if self.cipher.is_none() {
      return Err(btleplug::Error::RuntimeError(
        "Cipher not initialized".to_string(),
      ));
    }

    let mut custom_command_packet = protos::custom_commands::CommandWrapper::new();
    let start_cmd = protos::custom_commands::StartCmd::new();
    custom_command_packet.set_start_cmd(start_cmd);

    let mut custom_command_packet = custom_command_packet.write_to_bytes().unwrap();
    self
      .cipher
      .as_mut()
      .unwrap()
      .apply_keystream(custom_command_packet.as_mut());

    self
      .write_characteristic(
        BlueAirCharacteristic::CustomEndpoint,
        custom_command_packet.as_slice(),
      )
      .await?;

    let mut read_value = self
      .read_characteristic(BlueAirCharacteristic::CustomEndpoint)
      .await?;

    self
      .cipher
      .as_mut()
      .unwrap()
      .apply_keystream(read_value.as_mut());

    let custom_command_response =
      protos::custom_commands::CommandWrapper::parse_from_bytes(&read_value).unwrap();

    let start_response = custom_command_response.start_resp();
    let status = start_response.status.enum_value().unwrap();

    if status != protos::custom_commands::Status::Success {
      return Err(btleplug::Error::RuntimeError(format!(
        "Start response status: {:?}",
        status
      )));
    }

    Ok(())
  }

  pub async fn set_configuration(&mut self, config: Configuration) -> Result<()> {
    if self.cipher.is_none() {
      return Err(btleplug::Error::RuntimeError(
        "Cipher not initialized".to_string(),
      ));
    }

    for (field, value) in config.values() {
      let mut custom_command_packet = protos::custom_commands::CommandWrapper::new();
      let mut payload = protos::custom_commands::ConfigCmd::new();

      match field {
        ConfigurationEntry::ApiUrl => payload.set_api_url(value),
        ConfigurationEntry::AuthUrl => payload.set_auth_url(value),
        ConfigurationEntry::BrokerUrl => payload.set_broker_url(value),
        ConfigurationEntry::Region => payload.set_region(value),
        ConfigurationEntry::RandomText => payload.set_random_text(value),
        ConfigurationEntry::SecureRandom => payload.set_secure_random(value),
      }

      custom_command_packet.set_config_cmd(payload);

      let mut custom_command_packet = custom_command_packet.write_to_bytes().unwrap();
      self
        .cipher
        .as_mut()
        .unwrap()
        .apply_keystream(custom_command_packet.as_mut());

      self
        .write_characteristic(
          BlueAirCharacteristic::CustomEndpoint,
          custom_command_packet.as_slice(),
        )
        .await?;

      let mut read_value = self
        .read_characteristic(BlueAirCharacteristic::CustomEndpoint)
        .await?;

      self
        .cipher
        .as_mut()
        .unwrap()
        .apply_keystream(read_value.as_mut());

      let custom_command_response =
        protos::custom_commands::CommandWrapper::parse_from_bytes(&read_value).unwrap();

      let config_response = custom_command_response.config_resp();
      let status = config_response.status.enum_value().unwrap();

      if status != protos::custom_commands::Status::Success {
        return Err(btleplug::Error::RuntimeError(format!(
          "Config response status: {:?}",
          status
        )));
      }
    }

    self.is_configured = true;

    Ok(())
  }

  pub async fn wifi_connect(&mut self, ssid: &str, password: &str) -> Result<()> {
    if self.cipher.is_none() {
      return Err(btleplug::Error::RuntimeError(
        "Cipher not initialized.".to_string(),
      ));
    }

    if !self.is_configured {
      return Err(btleplug::Error::RuntimeError(
        "Device not configured.".to_string(),
      ));
    }

    let mut wifi_config_packet = protos::wifi_config::WiFiConfigPayload::new();
    let mut payload = protos::wifi_config::CmdSetConfig::new();

    payload.ssid = ssid.as_bytes().to_vec();
    payload.passphrase = password.as_bytes().to_vec();

    wifi_config_packet.set_cmd_set_config(payload);
    wifi_config_packet.msg =
      EnumOrUnknown::new(protos::wifi_config::WiFiConfigMsgType::TypeCmdSetConfig);

    let mut wifi_config_packet = wifi_config_packet.write_to_bytes().unwrap();
    self
      .cipher
      .as_mut()
      .unwrap()
      .apply_keystream(wifi_config_packet.as_mut());

    self
      .write_characteristic(
        BlueAirCharacteristic::ProvConfig,
        wifi_config_packet.as_slice(),
      )
      .await?;

    let mut read_value = self
      .read_characteristic(BlueAirCharacteristic::ProvConfig)
      .await?;

    self
      .cipher
      .as_mut()
      .unwrap()
      .apply_keystream(read_value.as_mut());

    let wifi_config_response =
      protos::wifi_config::WiFiConfigPayload::parse_from_bytes(&read_value).unwrap();
    let wifi_config_response = wifi_config_response.resp_set_config();

    let status = wifi_config_response.status.enum_value().unwrap();
    if status != protos::constants::Status::Success {
      return Err(btleplug::Error::RuntimeError(format!(
        "WiFi cmd set config response status: {:?}",
        status
      )));
    }

    let mut wifi_config_packet = protos::wifi_config::WiFiConfigPayload::new();
    let payload = protos::wifi_config::CmdApplyConfig::new();

    wifi_config_packet.msg =
      EnumOrUnknown::new(protos::wifi_config::WiFiConfigMsgType::TypeCmdApplyConfig);
    wifi_config_packet.set_cmd_apply_config(payload);

    let mut wifi_config_packet = wifi_config_packet.write_to_bytes().unwrap();
    self
      .cipher
      .as_mut()
      .unwrap()
      .apply_keystream(wifi_config_packet.as_mut());

    self
      .write_characteristic(
        BlueAirCharacteristic::ProvConfig,
        wifi_config_packet.as_slice(),
      )
      .await?;

    let mut read_value = self
      .read_characteristic(BlueAirCharacteristic::ProvConfig)
      .await?;

    self
      .cipher
      .as_mut()
      .unwrap()
      .apply_keystream(read_value.as_mut());

    let wifi_config_response =
      protos::wifi_config::WiFiConfigPayload::parse_from_bytes(&read_value).unwrap();
    let wifi_config_response = wifi_config_response.resp_apply_config();

    let status = wifi_config_response.status.enum_value().unwrap();
    if status != protos::constants::Status::Success {
      return Err(btleplug::Error::RuntimeError(format!(
        "WiFi cmd apply response status: {:?}",
        status
      )));
    }

    let start_time = Instant::now();
    let timeout = Duration::from_secs(10);
    loop {
      let mut wifi_config_packet = protos::wifi_config::WiFiConfigPayload::new();
      let payload = protos::wifi_config::CmdGetStatus::new();

      wifi_config_packet.msg =
        EnumOrUnknown::new(protos::wifi_config::WiFiConfigMsgType::TypeCmdGetStatus);
      wifi_config_packet.set_cmd_get_status(payload);

      let mut wifi_config_packet = wifi_config_packet.write_to_bytes().unwrap();
      self
        .cipher
        .as_mut()
        .unwrap()
        .apply_keystream(wifi_config_packet.as_mut());

      self
        .write_characteristic(
          BlueAirCharacteristic::ProvConfig,
          wifi_config_packet.as_slice(),
        )
        .await?;

      let mut read_value = self
        .read_characteristic(BlueAirCharacteristic::ProvConfig)
        .await?;

      self
        .cipher
        .as_mut()
        .unwrap()
        .apply_keystream(read_value.as_mut());

      let wifi_config_response =
        protos::wifi_config::WiFiConfigPayload::parse_from_bytes(&read_value).unwrap();
      let wifi_config_response = wifi_config_response.resp_get_status();

      let status = wifi_config_response.status.enum_value().unwrap();
      if status != protos::constants::Status::Success {
        return Err(btleplug::Error::RuntimeError(format!(
          "WiFi get status response status: {:?}",
          status
        )));
      }

      let sta_state = wifi_config_response.sta_state.enum_value().unwrap();
      if wifi_config_response.has_fail_reason()
        && sta_state != protos::wifi_constants::WifiStationState::Connecting
      {
        return Err(btleplug::Error::RuntimeError(format!(
          "WiFi config response has a fail reason: {:?} (span_state: {:?})",
          wifi_config_response.fail_reason(),
          sta_state
        )));
      } else if start_time.elapsed() >= timeout {
        return Err(btleplug::Error::RuntimeError(
          "WiFi config timeout".to_string(),
        ));
      } else if sta_state == protos::wifi_constants::WifiStationState::Connected {
        return Ok(());
      }
    }
  }

  async fn wifi_scan(&mut self) -> Result<Vec<WiFiResult>> {
    if self.cipher.is_none() {
      return Err(btleplug::Error::RuntimeError(
        "Cipher not initialized".to_string(),
      ));
    }

    // Start WiFi scan
    let mut wifi_scan_packet = protos::wifi_scan::WiFiScanPayload::new();

    let mut payload = protos::wifi_scan::CmdScanStart::new();
    payload.blocking = true;
    payload.passive = false;
    payload.group_channels = 0;
    payload.period_ms = 120;

    wifi_scan_packet.set_cmd_scan_start(payload);
    wifi_scan_packet.msg = EnumOrUnknown::new(protos::wifi_scan::WiFiScanMsgType::TypeCmdScanStart);

    let mut wifi_scan_packet = wifi_scan_packet.write_to_bytes().unwrap();
    self
      .cipher
      .as_mut()
      .unwrap()
      .apply_keystream(wifi_scan_packet.as_mut());

    self
      .write_characteristic(BlueAirCharacteristic::ProvScan, wifi_scan_packet.as_slice())
      .await?;

    let mut read_value = self
      .read_characteristic(BlueAirCharacteristic::ProvScan)
      .await?;

    self
      .cipher
      .as_mut()
      .unwrap()
      .apply_keystream(read_value.as_mut());

    let wifi_scan_response =
      protos::wifi_scan::WiFiScanPayload::parse_from_bytes(&read_value).unwrap();
    let wifi_scan_response = wifi_scan_response.resp_scan_start();

    if !wifi_scan_response.is_initialized() {
      return Err(btleplug::Error::RuntimeError(
        "Device did not responded to WiFi scan command".to_string(),
      ));
    }

    // Wait for scan to finish
    let mut scan_finished = false;
    let mut result_count = 0;

    let mut iter_count = 0;
    while !scan_finished && iter_count < 10 {
      let mut wifi_scan_packet = protos::wifi_scan::WiFiScanPayload::new();

      let payload = protos::wifi_scan::CmdScanStatus::new();

      wifi_scan_packet.set_cmd_scan_status(payload);
      wifi_scan_packet.msg =
        EnumOrUnknown::new(protos::wifi_scan::WiFiScanMsgType::TypeCmdScanStatus);

      let mut wifi_scan_packet = wifi_scan_packet.write_to_bytes().unwrap();
      self
        .cipher
        .as_mut()
        .unwrap()
        .apply_keystream(wifi_scan_packet.as_mut());

      self
        .write_characteristic(BlueAirCharacteristic::ProvScan, wifi_scan_packet.as_slice())
        .await?;

      let mut read_value = self
        .read_characteristic(BlueAirCharacteristic::ProvScan)
        .await?;

      self
        .cipher
        .as_mut()
        .unwrap()
        .apply_keystream(read_value.as_mut());

      let wifi_scan_response =
        protos::wifi_scan::WiFiScanPayload::parse_from_bytes(&read_value).unwrap();

      let status = wifi_scan_response.status.enum_value().unwrap();

      if status != protos::constants::Status::Success {
        return Err(btleplug::Error::RuntimeError(format!(
          "WiFi scan response status: {:?}",
          status
        )));
      }

      let wifi_scan_response = wifi_scan_response.resp_scan_status();

      scan_finished = wifi_scan_response.scan_finished;
      result_count = wifi_scan_response.result_count;
      iter_count += 1;
    }

    if !scan_finished {
      return Err(btleplug::Error::RuntimeError(
        "WiFi scan did not finish, timeout".to_string(),
      ));
    }

    // Get scan results
    let mut start_index = 0;
    let mut scan_results = Vec::new();

    while start_index < result_count {
      let mut wifi_scan_packet = protos::wifi_scan::WiFiScanPayload::new();

      let count = std::cmp::min(result_count - start_index, WIFI_PACKET_COUNT);
      let mut payload = protos::wifi_scan::CmdScanResult::new();
      payload.start_index = start_index as u32;
      payload.count = count;

      wifi_scan_packet.set_cmd_scan_result(payload);
      wifi_scan_packet.msg =
        EnumOrUnknown::new(protos::wifi_scan::WiFiScanMsgType::TypeCmdScanResult);

      let mut wifi_scan_packet = wifi_scan_packet.write_to_bytes().unwrap();
      self
        .cipher
        .as_mut()
        .unwrap()
        .apply_keystream(wifi_scan_packet.as_mut());

      self
        .write_characteristic(BlueAirCharacteristic::ProvScan, wifi_scan_packet.as_slice())
        .await?;

      let mut read_value = self
        .read_characteristic(BlueAirCharacteristic::ProvScan)
        .await?;

      self
        .cipher
        .as_mut()
        .unwrap()
        .apply_keystream(read_value.as_mut());

      let wifi_scan_response =
        protos::wifi_scan::WiFiScanPayload::parse_from_bytes(&read_value).unwrap();
      let status = wifi_scan_response.status.enum_value().unwrap();

      if status != protos::constants::Status::Success {
        return Err(btleplug::Error::RuntimeError(format!(
          "WiFi scan response status: {:?}",
          status
        )));
      }

      let wifi_scan_response = wifi_scan_response.resp_scan_result();

      println!("Scan results: {:?}", wifi_scan_response.entries);

      scan_results.extend(
        wifi_scan_response
          .entries
          .clone()
          .iter()
          .map(|entry| WiFiResult {
            ssid: String::from_utf8(entry.ssid.clone()).unwrap(),
            bssid: hex::encode(entry.bssid.clone()),
            channel: entry.channel,
            rssi: entry.rssi,
            security: entry.auth.enum_value().unwrap(),
          }),
      );
      start_index += count;
    }

    Ok(scan_results)
  }

  async fn write_characteristic(
    &self,
    characteristic: BlueAirCharacteristic,
    value: &[u8],
  ) -> Result<()> {
    match self.characteristics.get(characteristic.as_str()) {
      Some(char) => {
        self
          .peripheral
          .write(char, value, WriteType::WithResponse)
          .await?;
        Ok(())
      }
      None => Err(btleplug::Error::RuntimeError(
        "Characteristic not found".to_string(),
      ))?,
    }
  }

  async fn read_characteristic(&self, characteristic: BlueAirCharacteristic) -> Result<Vec<u8>> {
    match self.characteristics.get(characteristic.as_str()) {
      Some(char) => {
        let value = self.peripheral.read(char).await?;
        Ok(value)
      }
      None => Err(btleplug::Error::RuntimeError(
        "Characteristic not found".to_string(),
      ))?,
    }
  }
}
