#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <DHT.h>
#include <ArduinoOTA.h>
#include <HTTPClient.h>
#include <HTTPUpdate.h>
#include <ArduinoJson.h>
#include <WiFiManager.h>
#include <Preferences.h>

#include "esp_wifi.h"
#include "esp_task_wdt.h"
#include "mbedtls/gcm.h"
#include "mbedtls/base64.h"

#include "version.h"

// ==================================================

// --------------------------------------------------
// RTOS Task Handles
// --------------------------------------------------
TaskHandle_t mqttTaskHandle   = NULL;
TaskHandle_t sensorTaskHandle = NULL;
TaskHandle_t otaTaskHandle    = NULL;
TaskHandle_t wifiTaskHandle   = NULL;

SemaphoreHandle_t mqttMutex;
SemaphoreHandle_t configMutex;   // guards mqttServer/User/Pass + cachedSSID/PSK

// --------------------------------------------------
// Global State
// --------------------------------------------------
unsigned long lastReconnectAttempt   = 0;
int           wifiFailureCount       = 0;
bool          portalRunning          = false;
unsigned long lastPortalOpenAttempt  = 0;

#define PORTAL_MIN_REOPEN_INTERVAL_MS 60000UL

// Cached credentials — populated at boot from flash, reliable even
// after WiFi disconnects (WiFi.SSID() returns empty once the link
// drops). Always access via setCachedCredentials()/getCachedCredentials().
String cachedSSID = "";
String cachedPSK  = "";

WiFiManager wm;

// Allocated once in setupConfigPortal() and never freed — WiFiManager
// keeps raw pointers to these, and the portal can be reopened later
// from wifiTask, so they must outlive the whole program.
WiFiManagerParameter *custom_mqtt_server = nullptr;
WiFiManagerParameter *custom_mqtt_user   = nullptr;
WiFiManagerParameter *custom_mqtt_pass   = nullptr;

// --------------------------------------------------
// DHT11
// --------------------------------------------------
#define DHTPIN  4
#define DHTTYPE DHT11
DHT dht(DHTPIN, DHTTYPE);

// --------------------------------------------------
// AES Key (AES-128, 16 bytes) — used as the GCM key
// --------------------------------------------------
uint8_t AES_KEY[16];

// --------------------------------------------------
// MQTT / OTA globals
// --------------------------------------------------
String mqttServer = "";
String mqttUser   = "";
String mqttPass   = "";
int    mqttPort   = 8883;

volatile bool otaRequested  = false;
String        pendingOTAUrl = "";

// --------------------------------------------------
// CA Certificate (ISRG Root X1 — Let's Encrypt)
// --------------------------------------------------
const char* ca_cert = R"EOF(
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
)EOF";

WiFiClientSecure secureClient;
PubSubClient     client(secureClient);
Preferences      prefs;

// --------------------------------------------------
// Utility: bytes <-> hex
// --------------------------------------------------
String bytesToHex(const uint8_t *data, size_t len)
{
    String hex = "";
    for (size_t i = 0; i < len; i++)
    {
        char buf[3];
        sprintf(buf, "%02X", data[i]);
        hex += buf;
    }
    return hex;
}

void hexToBytes(const String &hex, uint8_t *out, size_t outLen)
{
    for (size_t i = 0; i < outLen; i++)
    {
        sscanf(
            hex.substring(i * 2, i * 2 + 2).c_str(),
            "%2hhx",
            &out[i]
        );
    }
}

// --------------------------------------------------
// AES Key initialisation (persisted in NVS)
// --------------------------------------------------
void initializeAESKey()
{
    prefs.begin("security", false);
    String storedKey = prefs.getString("aes_key", "");

    if (storedKey.length() != 32)
    {
        uint8_t newKey[16];
        for (int i = 0; i < 16; i++)
            newKey[i] = esp_random() & 0xFF;

        storedKey = bytesToHex(newKey, 16);
        prefs.putString("aes_key", storedKey);
        Serial.println("New AES key generated and saved");
    }
    else
    {
        Serial.println("AES key loaded from NVS");
    }

    hexToBytes(storedKey, AES_KEY, 16);
    prefs.end();
}

// --------------------------------------------------
// AES-128-GCM encrypt -> ivHex:base64(ciphertext):tagHex
//
// GCM gives confidentiality + integrity from a single key, so there is
// no HMAC key to manage (and no key-reuse risk), and no padding (so no
// padding-oracle-style surface either). A fresh random 96-bit nonce is
// generated per message; collision probability over a device's
// lifetime at a 5s publish interval is negligible.
// --------------------------------------------------
#define GCM_IV_LEN  12
#define GCM_TAG_LEN 16

String encryptGCM(const String &plainText)
{
    uint8_t iv[GCM_IV_LEN];
    for (int i = 0; i < GCM_IV_LEN; i++)
        iv[i] = esp_random() & 0xFF;

    size_t inputLen = plainText.length();

    // Bounds check before we do anything else — guards against a future
    // schema change silently overflowing the fixed base64 buffer below.
    size_t b64Capacity = 4 * ((inputLen + 2) / 3) + 4;
    if (inputLen == 0 || b64Capacity > 700)
    {
        Serial.println("encryptGCM: payload size out of bounds — refusing");
        return "";
    }

    uint8_t output[inputLen];
    uint8_t tag[GCM_TAG_LEN];

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, AES_KEY, 128);
    if (rc != 0)
    {
        mbedtls_gcm_free(&gcm);
        Serial.println("encryptGCM: setkey failed");
        return "";
    }

    rc = mbedtls_gcm_crypt_and_tag(
        &gcm, MBEDTLS_GCM_ENCRYPT,
        inputLen,
        iv, GCM_IV_LEN,
        NULL, 0,                          // no additional authenticated data
        (const uint8_t*)plainText.c_str(), output,
        GCM_TAG_LEN, tag
    );
    mbedtls_gcm_free(&gcm);

    if (rc != 0)
    {
        Serial.println("encryptGCM: encrypt failed");
        return "";
    }

    size_t        outLen = 0;
    unsigned char base64Buf[700];
    mbedtls_base64_encode(base64Buf, sizeof(base64Buf), &outLen, output, inputLen);
    base64Buf[outLen] = '\0';

    String ivHex  = bytesToHex(iv, GCM_IV_LEN);
    String tagHex = bytesToHex(tag, GCM_TAG_LEN);

    return ivHex + ":" + String((char*)base64Buf) + ":" + tagHex;
}

// --------------------------------------------------
// Firmware version compare (simple semver, "X.Y.Z")
// Returns >0 if a is newer than b, <0 if older, 0 if equal.
// Falls back to "treat as different" if either string doesn't parse.
// --------------------------------------------------
int compareVersions(const String &a, const String &b)
{
    int aMaj = 0, aMin = 0, aPatch = 0;
    int bMaj = 0, bMin = 0, bPatch = 0;

    int aMatched = sscanf(a.c_str(), "%d.%d.%d", &aMaj, &aMin, &aPatch);
    int bMatched = sscanf(b.c_str(), "%d.%d.%d", &bMaj, &bMin, &bPatch);

    if (aMatched < 2 || bMatched < 2)
        return (a == b) ? 0 : 1;

    if (aMaj != bMaj) return aMaj - bMaj;
    if (aMin != bMin) return aMin - bMin;
    return aPatch - bPatch;
}

// --------------------------------------------------
// Timestamp helper — time(nullptr) reads as a small epoch value before
// NTP has synced; treat that as "unsynced" rather than publishing a
// misleading timestamp. Telemetry also carries millis() separately as
// an always-valid monotonic fallback.
// --------------------------------------------------
unsigned long getTimestamp()
{
    time_t now = time(nullptr);
    if (now < 1577836800) // 2020-01-01T00:00:00Z
        return 0;
    return (unsigned long)now;
}

// --------------------------------------------------
// Per-device config portal password, derived from the efuse MAC.
// Still serial-only rather than a physical label — fine for
// prototyping, but print this on a label at manufacture time for a
// real deployment instead of relying on serial access.
// --------------------------------------------------
String getPortalPassword()
{
    uint64_t mac = ESP.getEfuseMac();
    char buf[13];
    snprintf(buf, sizeof(buf), "%012llX", mac);
    return "ESP-" + String(buf).substring(6);
}

// --------------------------------------------------
// Shared-state accessors (configMutex-protected)
// --------------------------------------------------
void setCachedCredentials(const String &ssid, const String &psk)
{
    if (xSemaphoreTake(configMutex, pdMS_TO_TICKS(1000)))
    {
        cachedSSID = ssid;
        cachedPSK  = psk;
        xSemaphoreGive(configMutex);
    }
}

bool getCachedCredentials(String &ssidOut, String &pskOut)
{
    bool ok = false;
    if (xSemaphoreTake(configMutex, pdMS_TO_TICKS(1000)))
    {
        ssidOut = cachedSSID;
        pskOut  = cachedPSK;
        ok = ssidOut.length() > 0;
        xSemaphoreGive(configMutex);
    }
    return ok;
}

// --------------------------------------------------
// OTA over HTTP
//
// NOTE: left exactly as in the original sketch. otaClient.setInsecure()
// and the lack of any firmware-image signature check are a known,
// separate issue — out of scope for this revision.
// --------------------------------------------------
void doOTA(String url)
{
    Serial.println("========== OTA UPDATE ==========");
    Serial.print("Downloading: ");
    Serial.println(url);

    WiFiClientSecure otaClient;
    otaClient.setInsecure();
    httpUpdate.rebootOnUpdate(true);
    httpUpdate.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);

    t_httpUpdate_return ret = httpUpdate.update(otaClient, url);

    switch (ret)
    {
        case HTTP_UPDATE_FAILED:
            Serial.printf(
                "Update failed (%d): %s\n",
                httpUpdate.getLastError(),
                httpUpdate.getLastErrorString().c_str()
            );
            break;
        case HTTP_UPDATE_NO_UPDATES:
            Serial.println("No update available");
            break;
        case HTTP_UPDATE_OK:
            Serial.println("Update successful");
            break;
    }
}

// --------------------------------------------------
// MQTT callback
// --------------------------------------------------
void callback(char* topic, byte* payload, unsigned int length)
{
    String msg = "";
    for (unsigned int i = 0; i < length; i++)
        msg += (char)payload[i];

    Serial.print("Topic: ");   Serial.println(topic);
    Serial.print("Payload: "); Serial.println(msg);

    if (String(topic) == "home/esp32/update")
    {
        StaticJsonDocument<512> doc;
        DeserializationError err = deserializeJson(doc, msg);
        if (err)
        {
            Serial.println("Invalid OTA JSON");
            return;
        }

        String newVersion = doc["version"].as<String>();
        String otaUrl     = doc["url"].as<String>();

        Serial.print("Current Version:   "); Serial.println(FW_VERSION);
        Serial.print("Available Version: "); Serial.println(newVersion);

        if (compareVersions(newVersion, FW_VERSION) <= 0)
        {
            Serial.println("Not newer than current version — ignoring");
            return;
        }

        Serial.println("New firmware detected — scheduling OTA");
        pendingOTAUrl = otaUrl;
        otaRequested  = true;
    }
}

// --------------------------------------------------
// loadCredentialsFromFlash
//
// Reads WiFi credentials from the ESP32 WiFi NVS partition directly
// via esp_wifi_get_config(). This is the only reliable source once
// WiFi has disconnected — WiFi.SSID() / WiFi.psk() go empty after the
// link drops.
// --------------------------------------------------
void loadCredentialsFromFlash()
{
    wifi_config_t conf;
    memset(&conf, 0, sizeof(conf));

    if (esp_wifi_get_config(WIFI_IF_STA, &conf) == ESP_OK)
    {
        String ssid = String((char*)conf.sta.ssid);
        String psk  = String((char*)conf.sta.password);

        if (ssid.length() > 0)
        {
            setCachedCredentials(ssid, psk);
            Serial.print("Credentials loaded from flash. SSID: ");
            Serial.println(ssid);
        }
        else
        {
            Serial.println("No credentials stored in flash yet.");
        }
    }
    else
    {
        Serial.println("esp_wifi_get_config failed.");
    }
}

// --------------------------------------------------
// openConfigPortal
//
// Centralised, rate-limited portal opener. Without rate limiting, an
// attacker who can knock the device off WiFi repeatedly could force
// the portal to reopen in a tight loop; this caps reopens to once a
// minute and persists a counter so the operator can see in MQTT
// ("home/esp32/portal_events") whether the portal has been opening
// more than expected.
// --------------------------------------------------
void openConfigPortal()
{
    if (portalRunning) return;

    unsigned long now = millis();
    if (lastPortalOpenAttempt != 0 &&
        now - lastPortalOpenAttempt < PORTAL_MIN_REOPEN_INTERVAL_MS)
    {
        Serial.println("Portal reopen suppressed — rate limited");
        return;
    }
    lastPortalOpenAttempt = now;

    prefs.begin("security", false);
    uint32_t opens = prefs.getUInt("portal_opens", 0) + 1;
    prefs.putUInt("portal_opens", opens);
    prefs.end();

    String pwd = getPortalPassword();
    Serial.print("Opening config portal. Password: ");
    Serial.println(pwd);

    wm.setConfigPortalBlocking(false);
    wm.startConfigPortal("ESP32_Config", pwd.c_str());
    portalRunning = true;
}

// --------------------------------------------------
// onPortalSave
//
// Plain function (not a [&]-capturing lambda) reading from file-scope
// WiFiManagerParameter pointers, so it stays valid no matter how many
// times the portal is reopened over the device's lifetime.
// --------------------------------------------------
void onPortalSave()
{
    if (!custom_mqtt_server || !custom_mqtt_user || !custom_mqtt_pass)
        return; // defensive — should be unreachable if setup ran correctly

    String newServer = String(custom_mqtt_server->getValue());
    String newUser   = String(custom_mqtt_user->getValue());
    String newPass   = String(custom_mqtt_pass->getValue());

    prefs.begin("config", false);
    prefs.putString("mqtt_server", newServer);
    prefs.putString("mqtt_user",   newUser);
    prefs.putString("mqtt_pass",   newPass);
    prefs.end();

    // Track config changes for the same visibility reason as portal_opens.
    prefs.begin("security", false);
    uint32_t saves = prefs.getUInt("config_saves", 0) + 1;
    prefs.putUInt("config_saves", saves);
    prefs.end();

    if (xSemaphoreTake(configMutex, pdMS_TO_TICKS(1000)))
    {
        mqttServer = newServer;
        mqttUser   = newUser;
        mqttPass   = newPass;
        xSemaphoreGive(configMutex);
    }

    Serial.println("MQTT config saved from portal");

    // Force an immediate reconnect against the new server/credentials
    // instead of waiting for the existing broker connection to drop on
    // its own — mqttTask re-reads mqttServer/User/Pass on its next
    // reconnect attempt.
    if (xSemaphoreTake(mqttMutex, pdMS_TO_TICKS(1000)))
    {
        client.disconnect();
        xSemaphoreGive(mqttMutex);
    }

    // WiFiManager has just written the new SSID/PSK to flash — give it
    // a tick, then re-read so wifiTask always has fresh values.
    delay(200);
    loadCredentialsFromFlash();
}

// --------------------------------------------------
// setupConfigPortal
//
// Boot strategy:
//   1. If flash has saved credentials, try them directly for up to
//      15 s (fast path).
//   2. If that succeeds, continue normally.
//   3. If it fails (router down at boot), open the non-blocking
//      portal so setup() can finish and wifiTask can own all retry +
//      portal logic.
//   4. If no credentials are stored at all (first boot), run the
//      BLOCKING portal until the user submits credentials — there is
//      nothing else to do anyway.
// --------------------------------------------------
void setupConfigPortal()
{
    prefs.begin("config", true);
    String savedServer = prefs.getString("mqtt_server", "");
    String savedUser   = prefs.getString("mqtt_user",   "");
    String savedPass   = prefs.getString("mqtt_pass",   "");
    prefs.end();

    // Heap-allocated, file-scope pointers — see the comment on the
    // declarations above for why this matters.
    custom_mqtt_server = new WiFiManagerParameter("server", "MQTT Server",   savedServer.c_str(), 100);
    custom_mqtt_user   = new WiFiManagerParameter("user",   "MQTT Username", savedUser.c_str(),   50);
    custom_mqtt_pass   = new WiFiManagerParameter("pass",   "MQTT Password", savedPass.c_str(),   50);

    wm.addParameter(custom_mqtt_server);
    wm.addParameter(custom_mqtt_user);
    wm.addParameter(custom_mqtt_pass);
    wm.setSaveParamsCallback(onPortalSave);

    // Read credentials that WiFiManager previously saved to flash.
    // Do this BEFORE any WiFi.begin() call while the stack is idle so
    // WiFi.SSID() / esp_wifi_get_config() are still populated.
    WiFi.mode(WIFI_STA);
    delay(100);
    loadCredentialsFromFlash();

    String ssid, psk;
    if (getCachedCredentials(ssid, psk))
    {
        Serial.print("Boot: connecting to saved SSID: ");
        Serial.println(ssid);

        WiFi.begin(ssid.c_str(), psk.c_str());

        unsigned long start = millis();
        while (WiFi.status() != WL_CONNECTED && millis() - start < 15000)
        {
            Serial.print(".");
            delay(500);
        }
        Serial.println();

        if (WiFi.status() == WL_CONNECTED)
        {
            Serial.println("Boot WiFi connected successfully.");
        }
        else
        {
            Serial.println("Boot WiFi failed. Starting non-blocking portal...");
            openConfigPortal();
        }
    }
    else
    {
        Serial.println("No saved credentials. Starting blocking portal...");
        String pwd = getPortalPassword();
        Serial.print("Portal password: ");
        Serial.println(pwd);
        wm.autoConnect("ESP32_Config", pwd.c_str());

        // After autoConnect the new credentials are in flash; cache them.
        loadCredentialsFromFlash();
    }

    // Read MQTT values — correct whether portal ran or not.
    if (xSemaphoreTake(configMutex, pdMS_TO_TICKS(1000)))
    {
        mqttServer = String(custom_mqtt_server->getValue());
        mqttUser   = String(custom_mqtt_user->getValue());
        mqttPass   = String(custom_mqtt_pass->getValue());
        xSemaphoreGive(configMutex);
    }

    Serial.print("MQTT Server: ");
    Serial.println(mqttServer);
}

// --------------------------------------------------
// RTOS Task: MQTT keep-alive + loop
// --------------------------------------------------
void mqttTask(void *pvParameters)
{
    esp_task_wdt_add(NULL);

    while (true)
    {
        esp_task_wdt_reset();

        if (!client.connected())
        {
            if (millis() - lastReconnectAttempt >= 5000)
            {
                lastReconnectAttempt = millis();

                // Snapshot config under configMutex, then release it
                // before touching the MQTT client — never hold both
                // mutexes at once (avoids any lock-ordering deadlock
                // risk against onPortalSave()).
                String localServer, localUser, localPass;
                if (xSemaphoreTake(configMutex, pdMS_TO_TICKS(500)))
                {
                    localServer = mqttServer;
                    localUser   = mqttUser;
                    localPass   = mqttPass;
                    xSemaphoreGive(configMutex);
                }

                Serial.print("Connecting MQTT... ");

                String clientId =
                    "ESP32_" + String((uint32_t)ESP.getEfuseMac(), HEX);

                if (xSemaphoreTake(mqttMutex, pdMS_TO_TICKS(1000)))
                {
                    // Re-applied every attempt so a server changed via
                    // the portal takes effect without a reboot.
                    client.setServer(localServer.c_str(), mqttPort);

                    if (client.connect(
                            clientId.c_str(),
                            localUser.c_str(),
                            localPass.c_str()))
                    {
                        Serial.println("connected");
                        client.subscribe("home/esp32/update");
                        Serial.println("Subscribed to OTA topic");

                        // Retained visibility into portal/config activity.
                        prefs.begin("security", true);
                        uint32_t portalOpens = prefs.getUInt("portal_opens", 0);
                        uint32_t configSaves = prefs.getUInt("config_saves", 0);
                        prefs.end();

                        StaticJsonDocument<128> evt;
                        evt["portal_opens"] = portalOpens;
                        evt["config_saves"] = configSaves;
                        String evtPayload;
                        serializeJson(evt, evtPayload);
                        client.publish("home/esp32/portal_events", evtPayload.c_str(), true);
                    }
                    else
                    {
                        Serial.print("failed rc=");
                        Serial.println(client.state());
                    }

                    xSemaphoreGive(mqttMutex);
                }
            }
        }

        if (xSemaphoreTake(mqttMutex, pdMS_TO_TICKS(100)))
        {
            client.loop();
            xSemaphoreGive(mqttMutex);
        }

        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

// --------------------------------------------------
// RTOS Task: OTA (ArduinoOTA + HTTP OTA)
// --------------------------------------------------
void otaTask(void *pvParameters)
{
    esp_task_wdt_add(NULL);

    while (true)
    {
        esp_task_wdt_reset();

        ArduinoOTA.handle();

        if (otaRequested)
        {
            otaRequested = false;
            Serial.println("Starting OTA...");
            Serial.printf(
                "OTA stack free before update: %u\n",
                uxTaskGetStackHighWaterMark(NULL)
            );

            // The download can legitimately run long enough to trip the
            // watchdog — drop this task's WDT subscription for the
            // duration, then re-subscribe once it returns.
            esp_task_wdt_delete(NULL);
            doOTA(pendingOTAUrl);
            esp_task_wdt_add(NULL);
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// --------------------------------------------------
// RTOS Task: DHT11 sensor -> encrypt -> publish
// --------------------------------------------------
void sensorTask(void *pvParameters)
{
    esp_task_wdt_add(NULL);

    while (true)
    {
        esp_task_wdt_reset();

        float temp = dht.readTemperature();
        float hum  = dht.readHumidity();

        if (!isnan(temp) && !isnan(hum))
        {
            StaticJsonDocument<512> doc;
            doc["temp"]      = temp;
            doc["hum"]       = hum;
            doc["device"]    = "ESP32_01";
            doc["timestamp"] = getTimestamp();  // 0 if NTP not yet synced
            doc["uptime_ms"] = millis();        // always-valid monotonic fallback
            doc["nonce"]     = String(esp_random());

            String payload;
            serializeJson(doc, payload);

            String encrypted = encryptGCM(payload);

            if (encrypted.length() == 0)
            {
                Serial.println("Encryption failed — skipping publish");
            }
            else if (xSemaphoreTake(mqttMutex, pdMS_TO_TICKS(1000)))
            {
                if (client.connected())
                {
                    Serial.print("Encrypted Length = ");
                    Serial.println(encrypted.length());

                    bool result = client.publish(
                        "home/esp32/encrypted",
                        encrypted.c_str()
                    );

                    Serial.print("Publish result = ");
                    Serial.println(result);
                }
                xSemaphoreGive(mqttMutex);
            }

#ifdef DEBUG_CRYPTO
            Serial.println("Plain:");
            Serial.println(payload);
            Serial.println("Encrypted:");
            Serial.println(encrypted);
#endif
        }
        else
        {
            Serial.println("DHT11 read failed");
        }

        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

// --------------------------------------------------
// RTOS Task: WiFi watchdog & reconnect
//
// Uses getCachedCredentials()/setCachedCredentials() throughout, so
// access is always configMutex-protected regardless of which task
// last updated them.
// --------------------------------------------------
#define PORTAL_RETRY_INTERVAL_MS   10000  // background retry period
#define PORTAL_PROCESS_INTERVAL_MS   100  // wm.process() poll interval
#define NTP_RESYNC_INTERVAL_MS   3600000UL // 1 hour

void wifiTask(void *pvParameters)
{
    esp_task_wdt_add(NULL);

    unsigned long lastPortalRetry = 0;
    unsigned long lastNtpSync     = 0;

    while (true)
    {
        esp_task_wdt_reset();

        // ── Connected ────────────────────────────────────────────────────
        if (WiFi.status() == WL_CONNECTED)
        {
            if (portalRunning)
            {
                Serial.println("WiFi connected. Closing config portal.");
                wm.stopConfigPortal();
                portalRunning    = false;
                wifiFailureCount = 0;
            }
            wifiFailureCount = 0;

            // Periodic resync so a missed first sync (or RTC drift over
            // long uptimes) doesn't leave timestamps wrong indefinitely.
            if (lastNtpSync == 0 || millis() - lastNtpSync >= NTP_RESYNC_INTERVAL_MS)
            {
                configTime(19800, 0, "pool.ntp.org", "time.nist.gov");
                lastNtpSync = millis();
            }

            vTaskDelay(pdMS_TO_TICKS(10000));
        }

        // ── Portal running — serve portal + retry cached creds ───────────
        else if (portalRunning)
        {
            unsigned long now = millis();

            if (now - lastPortalRetry >= PORTAL_RETRY_INTERVAL_MS)
            {
                lastPortalRetry = now;

                String ssid, psk;
                if (getCachedCredentials(ssid, psk))
                {
                    Serial.print(
                        "[Portal] Retrying cached SSID in background: "
                    );
                    Serial.println(ssid);

                    // AP+STA: WiFi.begin() runs while portal AP stays up
                    WiFi.begin(ssid.c_str(), psk.c_str());
                }
                else
                {
                    Serial.println(
                        "[Portal] No cached credentials — waiting for "
                        "user to submit portal form"
                    );
                }
            }

            if (WiFi.status() == WL_CONNECTED)
            {
                Serial.println(
                    "[Portal] Background retry succeeded. "
                    "Closing portal."
                );
                wm.stopConfigPortal();
                portalRunning    = false;
                wifiFailureCount = 0;
            }

            wm.process();
            vTaskDelay(pdMS_TO_TICKS(PORTAL_PROCESS_INTERVAL_MS));
        }

        // ── Disconnected, no portal — normal reconnect ───────────────────
        else
        {
            Serial.println("WiFi lost. Attempting reconnect...");

            String ssid, psk;
            if (getCachedCredentials(ssid, psk))
            {
                WiFi.disconnect(false, false);
                vTaskDelay(pdMS_TO_TICKS(500));

                Serial.print("Reconnecting to: ");
                Serial.println(ssid);

                WiFi.begin(ssid.c_str(), psk.c_str());

                int retries = 0;
                while (WiFi.status() != WL_CONNECTED && retries < 20)
                {
                    esp_task_wdt_reset();
                    Serial.print(".");
                    vTaskDelay(pdMS_TO_TICKS(500));
                    retries++;
                }
                Serial.println();
            }
            else
            {
                Serial.println("No cached credentials to reconnect with.");
            }

            if (WiFi.status() == WL_CONNECTED)
            {
                Serial.println("WiFi reconnected.");
                Serial.println(WiFi.localIP());
                wifiFailureCount = 0;
            }
            else
            {
                wifiFailureCount++;
                Serial.print("Reconnect failed. Count=");
                Serial.println(wifiFailureCount);

                if (wifiFailureCount >= 6)
                {
                    Serial.println(
                        "6 failures — starting non-blocking portal..."
                    );
                    openConfigPortal();
                    lastPortalRetry = 0; // trigger immediate first retry
                }
                else
                {
                    vTaskDelay(pdMS_TO_TICKS(10000));
                }
            }
        }
    }
}

// --------------------------------------------------
// Setup
// --------------------------------------------------
void setup()
{
    Serial.begin(115200);
    delay(3000);

    // Mutexes first — setupConfigPortal() below touches shared config
    // state and must not do so before they exist.
    configMutex = xSemaphoreCreateMutex();
    mqttMutex   = xSemaphoreCreateMutex();
    if (configMutex == NULL || mqttMutex == NULL)
    {
        Serial.println("Mutex creation failed — restarting");
        ESP.restart();
    }

    // Task watchdog: catches any of the RTOS tasks below hanging
    // instead of letting the device sit dead until someone notices.
    // NOTE: this signature matches arduino-esp32 core <3.0. On core
    // 3.x, switch to the esp_task_wdt_config_t struct-based
    // esp_task_wdt_init().
    esp_task_wdt_init(60, true);

    Serial.println("Initialising AES key...");
    initializeAESKey();

#ifdef DEBUG_CRYPTO
    Serial.print("AES Key: ");
    for (int i = 0; i < 16; i++)
        Serial.printf("%02X", AES_KEY[i]);
    Serial.println();
#endif

    dht.begin();

    // setupConfigPortal() handles all boot WiFi logic:
    //   - cached creds found -> try them, fall back to non-blocking portal
    //   - no creds at all   -> blocking portal until user configures
    setupConfigPortal();

    Serial.print("Firmware Version: ");
    Serial.println(FW_VERSION);

    // ArduinoOTA (LAN OTA) — only set up if connected
    ArduinoOTA.setHostname("ESP32-Sensor");
    ArduinoOTA.onStart([]()                { Serial.println("OTA Start"); });
    ArduinoOTA.onEnd([]()                  { Serial.println("\nOTA End"); });
    ArduinoOTA.onError([](ota_error_t err) { Serial.printf("OTA Error[%u]\n", err); });
    ArduinoOTA.begin();

    Serial.println("OTA Ready");
    Serial.print("IP: ");
    Serial.println(WiFi.localIP());

    // NTP — only meaningful when connected; wifiTask resyncs hourly and
    // retries connectivity on its own if this first attempt fails.
    if (WiFi.status() == WL_CONNECTED)
    {
        configTime(19800, 0, "pool.ntp.org", "time.nist.gov");
        struct tm timeinfo;
        int ntpRetries = 0;
        while (!getLocalTime(&timeinfo) && ntpRetries < 10)
        {
            Serial.println("Waiting for NTP...");
            delay(1000);
            ntpRetries++;
        }
        if (getLocalTime(&timeinfo))
            Serial.println("Time synced");
        else
            Serial.println("NTP failed — wifiTask will retry hourly once connected");
    }

    // TLS + MQTT
    secureClient.setCACert(ca_cert);

    if (xSemaphoreTake(configMutex, pdMS_TO_TICKS(1000)))
    {
        client.setServer(mqttServer.c_str(), mqttPort);
        xSemaphoreGive(configMutex);
    }
    client.setBufferSize(1024);
    client.setCallback(callback);

    // Launch RTOS tasks
    xTaskCreatePinnedToCore(
        mqttTask,   "MQTT",   16384, NULL, 3, &mqttTaskHandle,   1);
    xTaskCreatePinnedToCore(
        sensorTask, "Sensor",  6144, NULL, 2, &sensorTaskHandle,  1);
    xTaskCreatePinnedToCore(
        otaTask,    "OTA",    16384, NULL, 1, &otaTaskHandle,     0);
    xTaskCreatePinnedToCore(
        wifiTask,   "WiFi",    4096, NULL, 2, &wifiTaskHandle,    0);

    Serial.println("All RTOS tasks started");
}

// --------------------------------------------------
// Loop — all real work is in RTOS tasks
// --------------------------------------------------
void loop()
{
    vTaskDelay(pdMS_TO_TICKS(1000));
}
