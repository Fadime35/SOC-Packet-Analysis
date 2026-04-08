# SOC Packet Analysis Tool (CLI Tabanlı)

## Proje Amacı
Bu proje, bir SOC Analyst’in temel yeteneklerini göstermek amacıyla geliştirilmiş **CLI tabanlı bir ağ trafiği izleme ve anomali tespit aracıdır**.

- Ağ paketlerini canlı olarak yakalar  
- TCP SYN Port Scan, ICMP ve UDP Flood gibi anormallikleri tespit eder.  
- ALERT’leri hem CLI’de gösterir hem `alerts.log` dosyasına kaydeder.  
- Zamanlı özet rapor ile paket ve ALERT sayısını özetler  

---

## Özellikler

1. **TCP SYN Port Scan Detection**  
   - Bir IP’den aynı porta gelen SYN paketleri belirlenen eşik değerini aşarsa ALERT verir  

2. **ICMP Flood Detection**  
   - Bir IP’den gelen ICMP paketleri eşik değerini aşarsa ALERT verir  

3. **UDP Flood Detection**  
   - Bir IP’den gelen UDP paketleri eşik değerini aşarsa ALERT verir  

4. **Zamanlı Özet Rapor**  
   - Her 30 saniyede toplam paket sayısı ve ALERT sayısı CLI’de görüntülenir  

5. **CLI ve Log Desteği**  
   - ALERT’ler CLI’de anlık görünür  
   - `alerts.log` dosyasına kaydedilir.  

6. **Windows Uyumlu**  
   - Tek dosya çalışır, ekstra arayüz veya dosya gerekmez  
   - IP paketlerini filtreleyerek `Layer [IP] not found` uyarısını engeller.

---

## Kurulum ve Çalıştırma

1. Python 3.10+ yüklü olmalı  
2. **Scapy kütüphanesini yükle**

```bash
pip install scapy
```
3. Dosyayı kaydet: packet_analysis.py
4. Windows kullanıyorsan Admin olarak VSCode veya terminali çalıştır.
5. Scripti çalıştır:

   ```bash
   python packet_analysis.py
   ```

6. Paketler ve ALERT’ler CLI’de görülecek, alerts.log dosyasına kaydedilecek.

## Test Etme Önerisi
**ICMP paketi göndermek:**

```bash
ping 127.0.0.1
```

**TCP paketi göndermek (SYN test):**

```bash
import socket
s = socket.socket()
s.connect(("127.0.0.1", 80))
```

- Threshold değerleri düşük olduğu için her paketten ALERT tetiklenir.

## Geliştirme Notları

**Threshold değerleri gerçek ortamda artırılabilir:**

```bash
SYN_THRESHOLD = 5
ICMP_THRESHOLD = 10
UDP_THRESHOLD = 10
```

**İleri geliştirmeler:** ARP spoofing tespiti, kötü IP listesi, UDP port taraması, daha detaylı raporlama

## Proje Çıktıları

**CLI:** Canlı paket ve ALERT görüntüleme
**alerts.log:** ALERT kayıt dosyası
**Zamanlı özet rapor:** Paket ve ALERT istatistikleri
    
