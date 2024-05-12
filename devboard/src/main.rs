#![no_std]
#![no_main]

use core::task::Context;
use core::{future, mem};
use core::fmt::Error;
use defmt_rtt as _;

use embassy_executor::Spawner;
use embassy_nrf::interrupt::InterruptExt;
use embassy_nrf::peripherals::SAADC;
use embassy_nrf::saadc::{AnyInput, Input, Saadc};
use embassy_nrf::{bind_interrupts, interrupt, saadc};
use futures::future::{join, select, Either};
use futures::{pin_mut, Future, FutureExt};
use nrf_softdevice::ble::gatt_server::builder::ServiceBuilder;
use nrf_softdevice::ble::gatt_server::characteristic::{Attribute, Metadata, Properties};
use nrf_softdevice::ble::gatt_server::{CharacteristicHandles, NotifyValueError, RegisterError};
use nrf_softdevice::ble::security::SecurityHandler;
// global logger
use panic_probe as _;

use defmt::{info, *};
// use embassy_executor::Spawner;
use embassy_nrf::gpio::{AnyPin, Level, Output, OutputDrive, Pin};
use embassy_time::Timer;
use nrf_softdevice::ble::advertisement_builder::{
    Flag, LegacyAdvertisementBuilder, LegacyAdvertisementPayload, ServiceList, ServiceUuid16,
};
use nrf_softdevice::ble::{gatt_server, peripheral, Connection, Uuid};
use nrf_softdevice::{raw, Softdevice};

#[embassy_executor::task]
async fn softdevice_task(sd: &'static Softdevice) -> ! {
    sd.run().await
}

const BATTERY_SERVICE: Uuid = Uuid::new_16(0x180f);
const DEVICE_INFORMATION_SERVICE: Uuid = Uuid::new_16(0x180a);

const MANUFACTURER_NAME: Uuid = Uuid::new_16(0x2A29);
const SERIAL_NUMBER: Uuid = Uuid::new_16(0x2A25);
const BATTERY_LEVEL: Uuid = Uuid::new_16(0x2a19);

struct FlexService {
    value_handle: u16,
    cccd_handle: u16,
}

impl FlexService {
    pub fn new(sd: &mut Softdevice) -> Result<Self, RegisterError> {
        let uuid = Uuid::new_128(&0xc7e61440_1f83_438a_987f_937380d095dc_u128.to_le_bytes());
        let mut service_builder = ServiceBuilder::new(sd, uuid)?;

        let attr = Attribute::new(&[0u8, 0u8]);
        let metadata = Metadata::new(Properties::new().read().notify());
        let characteristic_builder = service_builder.add_characteristic(uuid, attr, metadata)?;
        let characteristic_handles = characteristic_builder.build();

        let _service_handle = service_builder.build();

        Ok(FlexService {
            value_handle: characteristic_handles.value_handle,
            cccd_handle: characteristic_handles.cccd_handle,
        })
    }

    pub fn flex_notify(&self, conn: &Connection, val: i16) -> Result<(), NotifyValueError> {
        gatt_server::notify_value(conn, self.value_handle, &val.to_le_bytes())
    }
}

struct BatteryService {
    value_handle: u16,
    cccd_handle: u16,
}

impl BatteryService {
    pub fn new(sd: &mut Softdevice) -> Result<Self, RegisterError> {
        let mut service_builder = ServiceBuilder::new(sd, BATTERY_SERVICE)?;

        let attr = Attribute::new(&[0u8]); // Unless im trippin, this is the actual value that we're tryna send
        let metadata = Metadata::new(Properties::new().read().notify()); // This is information like the CCCD info and stuff
        let characteristic_builder = service_builder.add_characteristic(BATTERY_LEVEL, attr, metadata)?; // This puts it all together into the service
        let characteristic_handles = characteristic_builder.build(); // Ig this is just a factory lol

        let _service_handle = service_builder.build(); // Another factory :sob:

        Ok(BatteryService {
            value_handle: characteristic_handles.value_handle,
            cccd_handle: characteristic_handles.cccd_handle,
        })
    }

    pub fn battery_level_get(&self, sd: &Softdevice) -> Result<u8, gatt_server::GetValueError> {
        let buf = &mut [0u8];
        gatt_server::get_value(sd, self.value_handle, buf)?;
        Ok(buf[0])
    }

    pub fn battery_level_set(&self, sd: &Softdevice, val: u8) -> Result<(), gatt_server::SetValueError> {
        gatt_server::set_value(sd, self.value_handle, &[val])
    }

    pub fn battery_level_notify(&self, conn: &Connection, val: u8) -> Result<(), gatt_server::NotifyValueError> {
        gatt_server::notify_value(conn, self.value_handle, &[val])
    }

    pub fn on_write(&self, handle: u16, data: &[u8]) {
        // TODO: Figure out exactly what this does when I develop the iOS app. iirc it should just
        // notify when someone subs to the service but maybe it doesn't idk and idk how to test
        // without the app lol.
        if handle == self.cccd_handle && !data.is_empty() {
            info!("battery notifications: {}", (data[0] & 0x01) != 0);
        }
    }
}

/*
Ok so here's the deal. Device information is a complex struct so i'll make it that and have that store the info
*/
struct DeviceInformation {
    pub manufacturer: Option<&'static str>,
    pub serial_number: Option<&'static str>,
}

/*
And we make a service for it as well, except notice that it has... nothing in it?? that's cuz
I don't need a way to access the data once I send it so I don't bother grabbing the handles to the info I send
and I send it as read so it's not like they can change it
*/
struct DeviceInformationService {}

impl DeviceInformationService {
    fn new(sd: &mut Softdevice, device_info: DeviceInformation) -> Result<Self, RegisterError> {
        let mut service_builder = ServiceBuilder::new(sd, DEVICE_INFORMATION_SERVICE)?;

        Self::add_device_info_str(&mut service_builder, MANUFACTURER_NAME, device_info.manufacturer)?;
        Self::add_device_info_str(&mut service_builder, SERIAL_NUMBER, device_info.serial_number)?;

        Ok(Self {})
    }

    fn add_device_info_str(
        service_builder: &mut ServiceBuilder,
        field_uuid: Uuid,
        field_value: Option<&'static str>,
    ) -> Result<Option<CharacteristicHandles>, RegisterError> {
        if let Some(field_value) = field_value {
            // If there is a value
            let attr = Attribute::new(field_value); // Create the attribute with that value
            let metadata = Metadata::new(Properties::new().read()); // Create the metadata and make it read only
            Ok(Some(
                service_builder.add_characteristic(field_uuid, attr, metadata)?.build(),
            )) // Return the built value
               // Note that its a Result with an error type but with an Option inside.
               // I never explicity write to the error. Why have it then? Note that before i build the handler I have a ?.
               // Idk what the word is but that "unwraps" the value and if there is an underlying error then (of the RegistryError type)
               // It returns that from this function.
        } else {
            Ok(None)
        }
    }
}

struct Server {
    _dis: DeviceInformationService,
    bas: BatteryService,
    fes: FlexService,
}

impl Server {
    fn new(sd: &mut Softdevice) -> Result<Self, RegisterError> {
        let dis = DeviceInformationService::new(
            sd,
            DeviceInformation {
                manufacturer: Some("Rezq"),
                serial_number: Some("12345678"),
            },
        )?;

        let bas = BatteryService::new(sd)?;

        let fes = FlexService::new(sd)?;

        Ok(Self { _dis: dis, bas: bas, fes: fes })
    }
}

impl gatt_server::Server for Server {
    type Event = ();

    fn on_write(
        &self,
        conn: &Connection,
        handle: u16,
        op: gatt_server::WriteOp,
        offset: usize,
        data: &[u8],
    ) -> Option<Self::Event> {
        self.bas.on_write(handle, data);
        None
    }
}

struct HidSecurityHandler {}

impl SecurityHandler for HidSecurityHandler {}

#[embassy_executor::task]
async fn blink(pin: AnyPin) {
    let mut led = Output::new(pin, Level::Low, OutputDrive::Standard);

    loop {
        led.set_high();
        Timer::after_millis(150).await;
        led.set_low();
        Timer::after_millis(150).await;
    }
}

async fn update_battery_counter_future<'a>(server: &'a Server, conn: &'a Connection) {
    let mut i: u8 = 0;
    loop {
        i += 1;

        let _ = server.bas.battery_level_notify(&conn, i);

        Timer::after_millis(5000).await;
    }
}

async fn update_resistor_value<'a>(saadc: &'a mut Saadc<'_, 1>, server: &'a Server, conn: &'a Connection) {
    loop {
        let mut buf = [0i16; 1];
        saadc.sample(&mut buf).await;

        // We only sampled one ADC channel.
        let adc_raw_value: i16 = buf[0];

        let _ = server.fes.flex_notify(conn, adc_raw_value);

        Timer::after_millis(1000).await;
    }
}

bind_interrupts!(struct Irqs {
    SAADC => saadc::InterruptHandler;
});

fn init_adc(pin: AnyInput, adc: SAADC) -> Saadc<'static, 1> {
    let config = saadc::Config::default();
    let channel_cfg = saadc::ChannelConfig::single_ended(pin.degrade_saadc());
    interrupt::SAADC.set_priority(interrupt::Priority::P3);
    let saadc = saadc::Saadc::new(adc, Irqs, config, [channel_cfg]);
    saadc
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut periph_config = embassy_nrf::config::Config::default();
    periph_config.gpiote_interrupt_priority = interrupt::Priority::P2;
    periph_config.time_interrupt_priority = interrupt::Priority::P2;
    let p: embassy_nrf::Peripherals = embassy_nrf::init(periph_config);

    let config = nrf_softdevice::Config {
        clock: Some(raw::nrf_clock_lf_cfg_t {
            source: raw::NRF_CLOCK_LF_SRC_XTAL as u8,
            rc_ctiv: 0,
            rc_temp_ctiv: 0,
            accuracy: raw::NRF_CLOCK_LF_ACCURACY_20_PPM as u8,
        }),
        conn_gap: Some(raw::ble_gap_conn_cfg_t {
            conn_count: 1,
            event_length: 3,
        }),
        conn_gatt: Some(raw::ble_gatt_conn_cfg_t { att_mtu: 256 }),
        gatts_attr_tab_size: Some(raw::ble_gatts_cfg_attr_tab_size_t {
            attr_tab_size: raw::BLE_GATTS_ATTR_TAB_SIZE_DEFAULT,
        }),
        gap_role_count: Some(raw::ble_gap_cfg_role_count_t {
            adv_set_count: 1,
            periph_role_count: 3,
            central_role_count: 3,
            central_sec_count: 0,
            _bitfield_1: raw::ble_gap_cfg_role_count_t::new_bitfield_1(0),
        }),
        gap_device_name: Some(raw::ble_gap_cfg_device_name_t {
            p_value: b"PoseFixer" as *const u8 as _,
            current_len: 9,
            max_len: 9,
            write_perm: unsafe { mem::zeroed() },
            _bitfield_1: raw::ble_gap_cfg_device_name_t::new_bitfield_1(raw::BLE_GATTS_VLOC_STACK as u8),
        }),
        ..Default::default()
    };

    let sd = Softdevice::enable(&config);
    let server = unwrap!(Server::new(sd));
    unwrap!(spawner.spawn(softdevice_task(sd)));

    // Spawned tasks run in the background, concurrently.
    unwrap!(spawner.spawn(blink(p.P0_15.degrade())));

    let resistor_pin = p.P0_02.degrade_saadc();
    let mut saadc = init_adc(resistor_pin, p.SAADC);
    saadc.calibrate().await;

    static ADV_DATA: LegacyAdvertisementPayload = LegacyAdvertisementBuilder::new()
        .flags(&[Flag::GeneralDiscovery, Flag::LE_Only])
        .services_16(
            ServiceList::Incomplete,
            &[ServiceUuid16::GENERIC_HEALTH_SENSOR, ServiceUuid16::BATTERY],
        )
        .full_name("PoseFixer")
        .build();

    static SCAN_DATA: LegacyAdvertisementPayload = LegacyAdvertisementBuilder::new()
        .services_16(ServiceList::Complete, &[ServiceUuid16::DEVICE_INFORMATION])
        .build();

    static SEC: HidSecurityHandler = HidSecurityHandler {};

    loop {
        let config = peripheral::Config::default();
        let adv = peripheral::ConnectableAdvertisement::ScannableUndirected {
            adv_data: &ADV_DATA,
            scan_data: &SCAN_DATA,
        };
        let conn = unwrap!(peripheral::advertise_pairable(sd, adv, &config, &SEC).await);
        info!("advertising done!");

        let battery_counter_future = update_battery_counter_future(&server, &conn);
        let update_resistor_value = update_resistor_value(&mut saadc, &server, &conn);
        
        // Run the GATT server on the connection. This returns when the connection gets disconnected.
        //
        // Event enums (ServerEvent's) are generated by nrf_softdevice::gatt_server
        // proc macro when applied to the Server struct above
        let gatt_server_future = gatt_server::run(&conn, &server, |_| {});

        pin_mut!(battery_counter_future);
        pin_mut!(gatt_server_future);
        pin_mut!(update_resistor_value);

        let joined_fut = join(battery_counter_future, update_resistor_value);

        let _ = match select(gatt_server_future, joined_fut).await {
            Either::Left((e, _)) => {
                info!("gatt_server encountered an error and stopped: {:?}", e);
            }
            Either::Right((_, _)) => {
                info!("bas/adc encountered an error and stopped");
            }
        };
    }
}