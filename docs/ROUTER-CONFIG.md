# Router yapılandırması

ddosd, `collector.listen` altındaki tüm UDP portlarında NetFlow v5/v9, IPFIX ve sFlow v5 paketlerini **otomatik** tanır. Varsayılan portlar 2055, 4739 ve 6343'tür. Aşağıdaki örneklerde collector adresi `10.0.0.50` olarak geçiyor.

> Örnekler şablondur. Komut sözdizimi platform ve yazılım sürümüne göre değişebilir; uygulamadan önce kendi sürümünüzün dokümanıyla doğrulayın.

## Genel öneriler

| Konu | Öneri | Neden |
|---|---|---|
| Telemetri tipi | Mümkünse **sFlow** | Paket örnekleri anında gelir; algılama yaklaşık 3–6 sn |
| NetFlow/IPFIX active timeout | **10 sn** (platformun izin verdiği en düşük değer) | Varsayılan 60 sn (Huawei'de 1 dk) algılamayı en az o kadar geciktirir |
| Inactive timeout | 15 sn | Tek paketlik sahte kaynaklı flow'lar (SYN flood) hızlı ihraç edilir |
| Örnekleme | Edge'de 1:1000 – 1:4000; düşük hacimli bağlantılarda 1:100 – 1:512 | Küçük saldırıları da görmek için yeterli örnek gerekir (`min_samples`) |
| Yön | **Ingress** (internetten gelen) arayüzlerde | Inbound saldırılar; outbound için müşteri yönlü ingress |
| Template timeout | 60 sn | Collector yeniden başladığında şablonsuz veri süresini kısaltır |
| Örnekleme oranı bildirimi | Flow içinde ya da options template ile gönderin | Gönderilmiyorsa `exporters[].sampling_rate` ile zorlayın; yanlış oran tüm eşikleri kaydırır |
| Sunucu | `sysctl -w net.core.rmem_max=33554432`; UDP portlarını firewall'da açın | Ani yüklerde UDP kaybını önler (Telemetri Kaynakları → "Kayıp") |

Şablonlarda şu alanlar bulunmalı:
- Kaynak ve hedef IP, protokol, kaynak ve hedef port
- TCP flag'leri
- Byte ve paket sayıları
- Başlangıç ve bitiş zamanları
- Giriş ve çıkış arayüzleri
- Mümkünse ICMP tipi/kodu ve fragment bilgisi

## Cisco IOS-XE (Flexible NetFlow / IPFIX)

```
flow record DDOS-REC
 match ipv4 source address
 match ipv4 destination address
 match ipv4 protocol
 match transport source-port
 match transport destination-port
 match interface input
 collect transport tcp flags
 collect interface output
 collect counter bytes long
 collect counter packets long
 collect timestamp absolute first
 collect timestamp absolute last
!
flow exporter DDOS-EXP
 destination 10.0.0.50
 source Loopback0
 transport udp 4739
 export-protocol ipfix
 template data timeout 60
 option sampler-table
!
flow monitor DDOS-MON
 record DDOS-REC
 exporter DDOS-EXP
 cache timeout active 10
 cache timeout inactive 15
!
sampler DDOS-SAMPLER
 mode random 1 out-of 1000
!
interface TenGigabitEthernet0/0/0
 ip flow monitor DDOS-MON sampler DDOS-SAMPLER input
```

## Cisco IOS-XR (NetFlow v9)

```
flow exporter-map DDOS-EXP
 version v9
  options interface-table timeout 60
  options sampler-table timeout 60
  template data timeout 60
 !
 transport udp 2055
 source Loopback0
 destination 10.0.0.50
!
flow monitor-map DDOS-MON
 record ipv4
 exporter DDOS-EXP
 cache timeout active 10
 cache timeout inactive 15
!
sampler-map DDOS-SAMPLER
 random 1 out-of 1000
!
interface HundredGigE0/0/0/0
 flow ipv4 monitor DDOS-MON sampler DDOS-SAMPLER ingress
```

## Juniper MX (inline-jflow, IPFIX)

```
set chassis fpc 0 sampling-instance DDOS
set services flow-monitoring version-ipfix template v4 ipv4-template
set services flow-monitoring version-ipfix template v4 flow-active-timeout 10
set services flow-monitoring version-ipfix template v4 flow-inactive-timeout 15
set services flow-monitoring version-ipfix template v4 template-refresh-rate seconds 60
set forwarding-options sampling instance DDOS input rate 1000
set forwarding-options sampling instance DDOS family inet output flow-server 10.0.0.50 port 4739
set forwarding-options sampling instance DDOS family inet output flow-server 10.0.0.50 version-ipfix template v4
set forwarding-options sampling instance DDOS family inet output inline-jflow source-address 10.0.0.1
set interfaces xe-0/0/0 unit 0 family inet sampling input
```

## Juniper EX/QFX, Arista (sFlow)

```
# Junos
set protocols sflow collector 10.0.0.50 udp-port 6343
set protocols sflow sample-rate ingress 1000
set protocols sflow polling-interval 20
set protocols sflow interfaces xe-0/0/0

# Arista EOS
sflow sample 1000
sflow polling-interval 20
sflow destination 10.0.0.50 6343
sflow source-interface Loopback0
sflow run
```

## Huawei (NetStream v9)

```
ip netstream export version 9
ip netstream export source 10.0.0.1
ip netstream export host 10.0.0.50 2055
ip netstream timeout active 1          # dakika; mümkün olan en düşük değer
ip netstream timeout inactive 15
ip netstream sampler random-packets 1000 inbound
interface GigabitEthernet0/0/1
 ip netstream inbound
```

## MikroTik RouterOS 7 (Traffic Flow / IPFIX)

```
/ip traffic-flow set enabled=yes interfaces=ether1 active-flow-timeout=10s inactive-flow-timeout=15s cache-entries=128k
/ip traffic-flow target add dst-address=10.0.0.50 port=4739 version=ipfix
```

## Linux sunucular / yazılım router'lar

```
# hsflowd (sFlow): /etc/hsflowd.conf
sflow { sampling = 1000  polling = 20  collector { ip = 10.0.0.50  udpport = 6343 } }

# softflowd (NetFlow v9)
softflowd -i eth0 -n 10.0.0.50:2055 -v 9 -t maxlife=10 -t general=15
```

---

## FlowSpec / RTBH: ddosd → ExaBGP → router

`mitigation.driver: exabgp` kullanıldığında ddosd, onaylanan kuralları ExaBGP'ye komut olarak yazar. ExaBGP de bunları router'a BGP FlowSpec (RFC 8955/8956) veya RTBH olarak duyurur. Örnek ExaBGP yapılandırması: `deploy/exabgp/exabgp.conf`.

Router tarafı için en iyi uygulamalar:
- Oturumu bir **route reflector**'a kurun, router'lara oradan dağıtın.
- ddosd oturumundan **yalnızca** FlowSpec ve /32 veya /128 RTBH kabul edin. Import policy'de prefix uzunluğu, community ve maksimum prefix sayısıyla sınırlayın.
- FlowSpec doğrulamasını (RFC 8955 §6) bu oturum için kapatmanız gerekebilir; ExaBGP hedef prefixin next-hop'u değildir.
- Önce bir lab router'ında `show` komutlarıyla kuralın kurulduğunu doğrulayın.

### Junos

```
set protocols bgp group DDOSD type external
set protocols bgp group DDOSD peer-as 65010
set protocols bgp group DDOSD neighbor 192.0.2.10 family inet flow no-validate DDOSD-FLOW-IN
set protocols bgp group DDOSD neighbor 192.0.2.10 family inet unicast prefix-limit maximum 200
set protocols bgp group DDOSD neighbor 192.0.2.10 import DDOSD-RTBH-IN
set policy-options policy-statement DDOSD-FLOW-IN term ok then accept
set policy-options community BLACKHOLE members 65535:666
set policy-options policy-statement DDOSD-RTBH-IN term rtbh from community BLACKHOLE
set policy-options policy-statement DDOSD-RTBH-IN term rtbh from route-filter 0.0.0.0/0 prefix-length-range /32-/32
set policy-options policy-statement DDOSD-RTBH-IN term rtbh then next-hop discard
set policy-options policy-statement DDOSD-RTBH-IN term rtbh then accept
set policy-options policy-statement DDOSD-RTBH-IN term reject then reject
set routing-options flow term-order standard
# doğrulama: show route table inetflow.0 extensive
```

### Cisco IOS-XR

```
route-policy DDOSD-IN
  pass
end-policy
router bgp 65000
 address-family ipv4 flowspec
 !
 neighbor 192.0.2.10
  remote-as 65010
  address-family ipv4 flowspec
   route-policy DDOSD-IN in
   validation disable
flowspec
 address-family ipv4
  local-install interface-all
# doğrulama: show flowspec ipv4 detail
```

UI'daki her mitigasyon kartında aynı kuralın ExaBGP, GoBGP, Junos ve IOS-XR karşılıkları gösterilir. Bu sayede BGP entegrasyonu olmadan da kural manuel olarak uygulanabilir.
