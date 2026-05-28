# IT594

# SRB

Dopunski repozitorijum za IT594 - Završni Master Rad
Univerzitet Metropolitan Beograd
Andrija Stojić 6355
Mentor:  Prof. Nemanja Zdravković

## Sadržaj repozitorijuma: 
1. Python Scripts - Namenske python skripte napise isključivo za potrebe ovog rada.
   1.1  rtcstats_dump_complete-4.py - Glavna skirpta korišćena prilikom analize rtcstats_dump fajlova koja obrađuje prikupljanje ice kandidata, metrike kvaliteta mreže, analizu simulcast slojeva, detekciju arhitekture više učesnika i ekstrakciju kodeka.
  1.2 rtcstats_dump_heartbeat - Dodatna skripta koja obrađuje heartbeat analizu rtcstats_dump fajlova.
  1.3 rtcstats_dump_screen_sharing - Dodatna skripta koja obrađuje, detektuje i analizira deljenje ekrana u rtcstats_dump fajlovima.
2. Python Scripts Output - Izlazi završenih analizi prilikom rada sve tri python skripte na fajlovima svih platformami.
3. RTCStats JSON Files - Sirovi JSON fajlovi dobijeni iz WebRTC kontrolne table u Chromium-baziranim browserima u toku trajanja video poziva.

### Neophodne biblioteke za rad Python skripti: 
json, os, sys, csv i statistics

Sve potrebne biblioteke su deo Python standardne biblioteke. 

#### Pristup dodatnim fajlovima

Svi fajlovi hvatanja paketa u Wiresharku (.pcapng) su hostovani na Google Drive-u univerzitetskog domena i mogu im pristupiti svi članovi univerziteta na linku ispod: 

[Pristup Wireshark Fajlovima](https://drive.google.com/drive/folders/1cvzr7qXXaMae-RgKoZEbIJNNo23oN1lY?usp=drive_link)

Pregled pcapng fajlova bez instaliranja Wireshark programa je moguće ostvariti direktno u browseru koristeći Wireview, koji je online pregledač paketa koji je kompatibilan sa Wireshark programom: 

[Wireview](https://wireview.github.io/)
Potrebno je prvo skinuti željeni .pcapng fajl sa Google Drive-a jer Wireview učitava samo lokalne fajlove, zatim kliknuti na browse dugme kada se pogram u potpunosti učita i odabrati skinuti fajl.

Svi paketi su hvatani u realnim mrežnim okruženjima sa namerno ostavljeniim pozadinskim procesima radi simulacije realističnog mrežnog okruženja kojem su ovi programi i namenjeni. 

##### Licence

Skripte za analizu su objavljene pod MIT Licencom. 
Fajlovi uhvaćenih paketa su dostupni za akademske svrhe.

# ENG

Supplementary repository for IT594 - Master's Thesis
Metropolitan University Belgrade
Andrija Stojić 6355
Mentor: Prof. Nemanja Zdravković

## Repository contents
1. Python Scripts — Purpose-built Python scripts written exclusively for the needs of this thesis.
   1.1 rtcstats_dump_complete_4.py - The main script used for analyzing RTCstats dump files, covering ICE candidate gathering, network quality metrics, simulcast layer analysis, multi-party architecture detection and codec extraction.
   1.2 rtcstats_dump_heartbeat.py - Supplementary script for heartbeat analyis of RTCStats dump files.
   1.3 rtcstats_dump_screen_sharing.py - Supplementary script that detects and analyzes screen sharing sessions within RTCStats dump files.
2. Python Scripts Output - Results of completed analyses produced by running all three Python scripts against the capture files of all platforms.
3. RTCStats JSON Files - Raw JSON files obtained from the WebRTC diagnostic interface in Chromium-based browsers during active video call sessions. 

### Required libraries

json, os, sys, csv, statistics

All required libraries are part of the Python standard library. 

#### Accessing additional files

All Wireshark packet capture files (.pcapng) are hosted on the university domain Google Drive and are accessible to all university memebers at the link bellow: 

[Access Wireshark Capture Files](https://drive.google.com/drive/folders/1cvzr7qXXaMae-RgKoZEbIJNNo23oN1lY?usp=drive_link)

Viewing .pcapng files without installing Wireshark is possible directly in the browser using Wireview, an online packet viewer compatible with Wireshark. 

[Wireview](https://wireview.github.io/)

Note: Wireview loads local files only. Download the desired .pcapng file from Google Drive first, then click the Browse button once Wireview has fully loaded and select the downloaded file.  

All packets were captured in real network environments with background proccesses intentionally left running in order to simulate the realistic network conditions these platforms are actually designed for. 

##### License

Analysis scripts are released under the MIT License.
Packet capture files are provided for academic purposes only. 
