---
title: SEC599 - notatki
id: 20210714123155
tag: #szkolenie #sans
author: '@srozb'
description: > 
    Moje notatki ze slajdów, w których zapisane nie to co
    najważniejsze, ale to co może mi umknąć.
---

* Zapamiętać: **omijać tego lektora z dala!!!**: Erik Van Buggenhout

# Introduction and Reconnaissance

## Adversary Emulation and Purple Team

* Unified Kill Chain lepiej modeluje poszczególne kroki adwersarza w stosunku do zwykłego KC (jest dokładniejszy).
* Red team powinien wykonywać okresowe działania zakończone raportem wspierającym Blue w rozwijaniu monitorowania/ID. Purple dla odmiany powinen wpływać na polepszanie zdolności Blue w sposób ciągły.
* Niby oczywiste, ale **ATT&CK nie jest kompletny**. Oznacza to, że trzeba też mieć świadomość technik poza tymi opisanymi.
* Kontrolki CIS - dobry początek do opracowania ogólnych zasad zapobiegania włamaniom
* Mimo to według ASD (Australian Signals Directorate) są 4 kontrolki mitygujące 85% zagrożeń: 1. Application Control 2. OS Patching 3. Application Patching 4. Restriction of Administrative Privs.
* Detekcje i Hardening (prewencje) buduje się z reguły na 4 filarach: 1. segmentacja sieci 2. centralna agragacja, przetwarzanie i analityka logów 3. hardening i monitoring końcówek (zazwyczaj są wektorem infekcji) 4. centralizacje ruchu wychodzącego (outbound proxy)
* segmentacja może być trudna w złożonym środowisku, ale czasami można osiągnąć quick winy np. blokując usługi wykorzystywane do lateral movementu przy użyciu FW
* checklisty do hardeningu można znaleźć na stronach NISTu[^1]. Warto zainteresować się formatem SCAP. 
* Security Technical Implementation Guides (STIG) - DoD General Purpose STIG
* Czasem można shardenować Windowsa przy użyciu PS używając formatu DSC (Desired State Configuration)
* MS oferuje Security Compliance Toolkit dla > Win10/2k16
* PingCastle - przykład toola do audytu środowiska AD
* Hardening linuksów najlepiej przy pomocy Ansible. Repo openstack udostępnia darmowe playbooki[^2]
* NSA/CSS opublikowali dobry guide dot. Windows Event Loga, jako źródła informacji dot. bezpieczeństwa. Opisane, które event id zbierać.[^3] MS też coś opublikował.[^4]
* Dobrym źródłem info o polepszeniu logowania WEL jest malwarearcheology.[^5] Dostępne jest również mapowanie ATT&CK na konkretne event id.
* Multum informacji dot. Sysmona również jest dostępne. M. im. ATT&CK-tagowanie reguł.[^6]

## Reconnaissance

* nic ciekawego

# Payload Delivery and Execution

## Common Delivery Mechanisms

* nic ciekawego

## Hindering Payload Delivery

* Rozdział zaczyna się od żartu, który śmieszy tylko instruktora.

### Obrona i atak sieci - NTLM&SMB relay

* Istnieją toole służące do omijania NACów (spoofing/mitm uwierzytelnionego urządzenia).[^7]
* NTLMRelay: NTLMv2 - to hmac-md5 gdzie kluczem jest najpierw nthash a uwierzytelnianą wiadomością username/domainname, następnie challange, potem timestamp… Kluczami w kolejnych etapach są hmaci wynikowe z poprzednich rund.
* Dalej o NTLMRelay: zgodnie z założeniem usługa, która uwierzytelnia klienta wysyła NTLMv2 Challenge, a otrzymuje od klienta NTLMv2 Response (który jest hashem NTLMv2 jak opisano wyżej). C i R są wysyłane do serwera uwierzytelniającego (kontroler domeny), który porównuje wartości po swojej stronie i odpowiada usłudze czy uwierzytelnienie się powiodło.
* Dalej o NTLMRelay: atak ntlmrelay jest oczywisty - wymuszenie C od celu ataku i przesłanie go do klienta celem uzyskania R. Ostatecznie wygenerowane przez klienta R wysyłane jest do pierwotnego celu ataku i poprawnie przez niego weryfikowane.
* Warto podkreślić, że Kerberos nie jest dość powszechny ponieważ wymaga wartości SPN, a jeśli np. oczekujemy uwierzytelnienia do usługi odwołując się przez IP to SPN nie jest znany/wykorzystywany. Dodatkowo wciąż pozostają zaszłości wymagające NTLMv2. Ergo - uwierzytelnienie NTLM rządko bywa wyłączane całkowicie.
* Responder wykorzystuje protokół LLMNR (który jest następcą NBT-NS) w celu wabienia ofiary - wykorzystanie rozwiązywania nazwy sieciowej. W obu przypadkach rozwiązywanie opiera się o multicast, w momencie kiedy klient nie dostaje odpowiedzi od DNSa.
* Responder potrafi również odpowiadać na zapytania LLMNR/NBT o `wpad`, co umożliwia MITMowanie ruchu http. Dodatkowo potrafi wymusić uwierzytelnienie NTLMv2 w celu przechwycenia hasha.
* Jako, że przechwycenie NTLMv2 może odbyć się na wiele sposobów (np. embed obrazka w dokumencie docx lub odnośnik do UNC w htmlu), **ruch wychodzący SMB powinien zawsze być wycięty na brzegu**.
* Ciekawy celem ataku są uwierzytelnione skanery podatności, które zwabione mogą wypluć wysokouprawniony hash NTLM.
* Sposoby mitygacji: 1. NBT-NS & LLMNR można wyłączyć w GPO. 2. SMB signing włączony jest domyślnie tylko na DC, ale można enrollnąć to na inne stacje. 3. WPADa można wyłączyć lub zadbać o odpowiedni wpis w DNSach. 4. Oczywiście segmentacja sieci i blokowanie niepotrzebnego ruchu.

### Mail Conrols, Web Proxies & Malware Sandboxing

* Często publikowane informacje o ruchu sieciowym generowanym przy okazji różnych rodzin malware jest na malware-traffic-analysis.[^8]

### Yara

* nic ciekawego

## Preventing payload execution

* nic ciekawego

# Exploitation, Persistence, and Command and Control

## Protecting Applications from Exploitation

### SDL

* Rozdział bazuje na Microsoft SDL. Składa się on z 7 faz i jest z powodzeniem stosowany przy developmencie w różnych firmach (poza MS).
* Kolejne fazy: 1. Training 2. Requirements (Sec. requirements, Risk assess.) 3. Design (design requirements, attack surface, threat modeling) 4. Implementation (Tools + static analysis) 5. Verification (Pentesting/fuzz/dynamic analysis) 6. Release (Create IR Plan) 7. Response (Execute IR Plan)
* W fazie implementacji warto blacklistować wykorzystanie przez devów funkcji uznanych za niebezpieczne (np. strcpy)
* Wyzwania przy implementacji SDL: 1. wsparcie C-lvl 2. nie może blokować kreatywności developerów, 3. nie ma złotego środka odpowiedniego dla każdego case'a 4. mimo to prawidłowa implementacja obniża koszty długoterminowo (ponoć)
* W przypadku Agile'a, Microsoft stworzył wersję specjalnie dla Agile/Scrum. Niektóre czynności wykonuje się co sprint, inne (mniej krytyczne) co bucket
* Threat modelling: 1. identyfikacja aktorów (TA) i ich celów 2. określenie pow. ataku 3. określenie technik wykorzystujących pow. ataku 4. trust boundries 5. mitygacja ryzyka i ocena ewentualnego impaktu (ilość i jakość)
* Microsoft wydał toola do modelowania zagrożenia[^9]

### Exploit Mitigation Techniques

* CFG działa w ten sposób, że tworzy bitmapę DLLek i pozwala tylko na CALLa do entrypointów funkcji
* CET / Shadow Stack (Intel) - Control Flow Enforcement Technology - zabezpiecza przed ROP. Mechanizm kopiuje return pointery do pamięci chronionej i przy RET porównuje wartości
* SEHOP - nie wiem jak działa, w pewnien sposób zabezpiecza możliwość nadpisania handlerów SEH, ale insturktor słabo to wytłumaczył
* MemGC, MS Isolated Heaps - zabezpiecza przed Use-after-Free w przeglądarkach
* ExploitGuard wczytuje PayloadCostam.dll i hookuje niektóre funkcje takie jak VirtualAlloc i w razie jak wykryje coś podejrzanego to zgłasza wyjątek
* Status ExploitGuarda można sprawdzić z PS poprzez `Get-ProcessMitigation-System`
* Export Address Filtering - w jakiś sposób utrudnia dostęp do tablicy EAT, blokując odczyt adresu funkcji. W ten sposób atakujący nie jest w stanie poznać adresów funkcji np. z kernel32.dll lub ntdll.dll
* Import Address Filtering - utrudnia hooking/wykonanie kodu poprzez podmianę adresu w IAT, ponieważ adres ten musi znajdować się wewnątrz dllki - inaczej blok.
* MASLR (Mandatory ASLR) - randomizuje bazę modułów, nawet jeśli zostały skompilowane w sposób uniemożliwijący rebase
* BASLR (Bottom-Up ASLR) - niejasne, losuje jakąś liczbę i poprzedza bazę przez random * 64kB bloki.
* Block Remote Images - blokuje możliwość wczytywania dllek ze ścieżek UNC - w celu utrudnienia ROPa. Bez sensu - po co tu ROP jak wczytanie dllki odpala DllMaina...
* Validate Heap Integrity - dodaje guard pages (32kb) do początków stert aby upewnić się, że nie nastąpiła ingerencja
* Arbitary Code Guard - upewnia się, że  adresy przekazywane do krytycznych funkcji takich jak VirtualProtect czy VAlloc nie są na stosie, czyli, że nie próbuje się zmienić uprawnień stosu. To może powodoważ problemy z kodem C# czy innym JITowym
* Validate API Invocation - upewnia się, że nie wskakujemy z wykonaniem kodu do krytycznych funkcji takich jak VAlloc/Protect przy użyciu instrukcji RET
* Simulate Execution (SimExec) - symuluje wykonanie kolejnych 15 instrukcji, jeśli napotka na RET, sprawdza czy wykonanie tej instrukcji spowoduje powrót do callera.
* Validate Stack Integrity/Stack Pivot Protection - sprawdza czy Stack Pointer wskazuje na wartość w limicie wielkości stacka (bazując na TIB)
* Code Integrity Guard, pozwala wczytywać tylko obrazy podpisane przez MS lub MS Store - chyba nie chodzi o DLL tylko o exe - por. "VID"
* Block Untrusted Fonts - okazuje się, że dużo pracy związanej z fontami wykonuje się w kernel-space. Wobec tego ten mechanizm umożliwia wczytywanie fontów tylko z katalogu Windows Fonts. Duqu APT wykorzystywał złośliwe fonty.
* Validate Handle Usage - sprawdza czy na pewno adres uchwytu jest prawidłowy aby zapobiec wykonaniu kodu kiedy tworzy się nowy proces wykorzystujący uchwyty procesu macierzystego
* Disable Extension Points - blokuje stare mechanizmy rozszerzania aplikacji np. AppInit_DLLs
* Disable Win32k System Calls - jak nazwa wskazuje uniemożliwia wykonywanie wywoływań win32k - nie jasne - syscalli? sysenter? 
* Do Not Allow Child Processes - uniemożliwia spawnowanie procesów potomnych dla konkretnego procesu
* Validate Image Dependency - wymaga żeby DLLka ładowana przez proces była podpisana przez MS
* Block Low Integrity Images - uniemożliwia wczytywanie obrazów (exeków?) z Low Integroty/Untrusted
* Core Isolation - coś a la Credential Guard - sterowniki i kluczowe procesy uruchamiane są w isolated area (odizolowanym fragmencie pamięci)

## Avoiding Installation

### Typical Persistence Strategies

* Instruktor dzieli persistence na kernel i user-space
* Persystencja nie wymaga uprawnień administracyjnych i nie można jej zapobiec (całkowicie)

### How do adversaries achieve persistence

* Jednym z rejestrów wykorzystywanych do persystencji jest `UserInitMprLogonScript` (HKCU) - skrypty logon
* Czasami persystencja może być zaszyta w innym mechanizmie ale pobierać payload z rejestru
* Jeśli właczono `SafeDllSearchMode` to Current Directory wędruje prawie na sam dół (przed %PATH%)
* Stworzenie BITS joba przetrwa restart komputera aż przez 90 dni i może wtedy działać jako mechanizm persystencji dzięki switchowi `SetNotifyCmdLine`. Można wykrywać `bitsadmin.exe /list /allusers /verbose`, oraz w WELu
* COM object hijacking jest ciekawy bo okazuje się, że czytając rejestr CLSID z HKCU ma wyższy priorytet niż HKLM, co oznacza, że użytkownik może zapisać w rejestrze clsid wskazujący na dllkę na dysku
* Można wrzucić comproxy, który umożliwia wczytanie prawidłowej dllki, ale wykonuje złośliwy kod.
* Trudno zapobiec i nie łatwo wykrywać, można porównywać CLSID dostępne w HKCU i HKLM - nie powinno być duplikatów

## Foiling Command and Control

### Detecting Command and Control channels

* Również ciężko zapobiec komunikacji C2 ze względu na różnorodność ruchu sieciowego (dozwolonego), a adwersarz może wykorzystać chociażby twittera
* C2Matrix jest fajną tabelką, która porównuje zdolności różnych C2 - np. obsługiwane protokoły, crypto, i inne funkcje[^10]
* Jest projekt SANS C2Slingshot, który jest VMką z dostępnymi wieloma C2
* Adwersarze starają się wtopić w szum - np. wykorzystywać kanał podobny do komunikacji CDNowej
* Domain Fronting - popularna taktyka wykorzystująca różnicę pomiędzy TLS SNI a nagłówkiem http `host`. Na skutek braku reenkrypcji TLS, tylko SNI jest czytane (można ściemnić, że jest legitne), a nagłówek host może wskazywać na prawdziwego hosta. W ten sposób można chociażby ominąć kategoryzacje web proxy.
* Wykrywanie i przeciwdziałanie C2 zawsze wymaga limitowania ruchu na zewnątrz i wykorzystania jakiegoś pośrednika (własne DNSy, własne Proxy)
* Wykrywanie zazwyczaj opiera się na szukaniu anomalii (czasowych, lub dziwnych/długich wartości w polach itp.)
* Można wykorzystać freq.py, który szuka DGA, tak jakbyśmy wciąż żyli w latach 90
* RITA parsuje logi Zeeka i szuka śladów C2

# Lateral Movement

## Protecting Administrative Access

### Active Directory Security Concepts

* Lateral movement w organizacji trwa dość długo (80% czasu ataku) i to jest dobry moment na wykrycie

### Principle of Least Privilege and UAC

* Według Microsoft użytkownicy z grupy Domain Admins powinni być wykorzystywani tylko w przypadku awarii, nigdy do zwykłych administracyjnych czynności
* JEA (Just Enough Admin) - ciekawy sposób agresywnego ograniczenia uprawnień dla administratora
* Microsoft proponuje 3 poziomy administratorów (domenowi, serwerowi, Ci od stacji) - i proponuje ich segmentować
* Użytkownik z upr. administracyjnymi ma właczony UAC. Oznacza to, że aplikacje uruchamia bez uprawnień dopóki o to eksplicite nie poprosi (run as admin). Win 7+ ma 4 poziomy UAC (Never, Low, Med, High). Ten mechanizm jest dziurawy i nie ma co mu ufać
* Jest sporo opcji GPO, które kontrolują jak działa UAC, kiedy przyciemnia ekran i na co ma pozwalać
* Jest wiele sposobów na UAC bypass, przeszło 30 checków implementuje UACME[^11]
* Kluczowym wnioskiem jest to, aby użytkownicy mieli osobne stacje/konta dla prac zwykłych i administracyjnych

### Privilege Escalation Techniques in Windows

* Ścieżki w których można szukać pliku `Unattend.xml`: `C:\Windows\Panther`, `C:\Windows\Panther\Unattend`, `C:\Windows\System32`, `C:\Windows\System32\sysprep`
* Poświadczenia zawarte w GPP (`CPassword`) można znaleźć w SYSVOLu, są szyfrowane AESem, przy użyciu 32bitowego klucza (zapewne rozciągniętego do 128/256), który został opublikowany w artykule MSDN. Można ich szukać `findstr /S cpassword %LOGONSERVER%\sysvol\*.xml`
* `AlwaysInstallElevated` to ustawienie polityki GPO, które można włączyć lokalnie przy pomocy klucza w rejestrze `HKCU\Software\Policies\Microsoft\Windows\Installer (AlwaysInstallElevated/DWORD 0/1)`. Pozwala ono instalować użytkownikom pliki MSI korzystając z uprawnień administracyjnych

## Key Attack Strategies against AD

### Abusing Local Admin Privileges to Steal More Credentials

* Rotten potato - technika pozwalająca eslakować się z konta serwisowego do SYSTEM (poprzez manipulacje tokenem)
* Domain Cached Credentials - zazwyczaj 10 ostatnio używanych poświadczeń na stacjach roboczych - trzeba łamać, nie można wykorzystać do pass-the-hash.
* W Win8/10 poświadczenia tekstem jawnym nie zawsze są w pamięci, ale hashe NTLM wystarczą do PtH
* Dobrym zabezpieczeniem przed dumpowaniem poświadczeń jest mechanizm _Domain Protected Users_. Jest to polityka AD i można ją zastosować do użytkowników lub grup, którzy będą chronieni w następujący sposób: 1. CredSSP i WDigest nie będą cacheować poświadczeń jawnym tekstem 2. Kerberos będzie używał AES128, AES256 i nie będzie cachowania poświadczeń tekstem jawnym, ani kluczy z długim czasem ekspiracji 3. Poświadczenia nie będą lokalnie cachowane w celach uwierzytelnienia offline 4. W domenie Windows Server 2012 R2, nie będzie możliwe uwierzytelnienie NTLM
* Protected Process Light (PPL) - od Windowsa 8, można odpalić lsassa w tym trybie, jednak mimikatz radzi sobie z PPL poprzez instalcje sterownika i operacje w kernel-space
* Remote Credential Guard nie działa jak Credential Guard (brak użycia wirtualizacji). Sprawia, że KRBTGT pozostaje na stacji lokalnej po podłaczeniu RDP, co uniemożliwia dump TGT na docelowej maszynie. W przypadku łączenia się dalej do kolejnych serwerów, TGT wciąż nie opuszcza oryginalnej stacji, dzięki czemu nie może być dumpnięty a SSO działa. Wciąż istnieje jednak ryzyko dumpnięcia Service Ticket, co oznacza, że atakujący będzie miał dostęp do tych zasobów, do których uzyskano service ticket.
* RestrictedAdminMode - kontrolka sprawiająca, że uwierzytelniony zdalnie administrator posiada prawa tylko do lokalnego komputera (uruchamia aplikacje w kontekście local admin). Microsoft zaleca to w scenariuszach "helpdesk"

### Kerberos attacks: Kerberoasting, Silver Tickets, Over-PtH

 * Kerberos w ogromnym skrócie i uproszczeniu: 1. klient uwierzytelnia się w KDC i uzyskuje TGT, który zawiera w sobie PAC (informacje o uprawnieniach klienta). 2. Klient ponownie komunikuje się z KDC, tym razem wysyła TGT i uzyskuje ST, w którym informacje o uprawnieniach PAC zostaną przepisane z TGT. 3. Klient przedstawi ST usłudzę, do której chce uzyskać dostęp, a ona nie będzie go weryfikowała bo ufa zawartemu w tickecie podpisowi.
 * KRBTGT to KDC long-term secret key (domain key) - właśnie on jest wykorzystywany do szyfrowania AS-REP (authentication server - response) oraz podpisania PACa
 * Poza tym również klient i usługa posiadają klucze long-term secret - często generowane na podstw. hasła
 * Kerberoasting polega na tym, że klient prosi o service ticket dla konkretnej usługi i go otrzymuje. Service ticket zawiera porcję przeznaczoną dla usługi i zaszyfrowaną jej hashem NTLM, który następnie można próbować złamać. Konta, które warto kerberoastować: AGPMServer, MSSQL/MSSQLSvc, FIMService, STS (Vmware)
 * W celu wykrywania kerberoastingu można posłużyć się EventID 4769
 * Over-Pass-the-Hash polega na tym, że szyfrując timestamp przy użyciu którejś z dopuszczonych metod w AD (np. rc4_hmac_md5), można uzyskać TGT i w ten sposób sfałszować tożsamość. Nawet jeśli ntlmv2 jest wyłączony to w ten sposób można przeprowadzić wersje kerberosową PtH.
 * Szczególnie cwanym pomysłem jest wykorzystywanie nowoczesnych schematów szyfrowania (np. tych opartych o AES), co dodatkowo zmniejsza ryzyko wykrycia ataku

### Moving laterally through the environment

* nic ciekawego

## How can we detect lateral movement?

### Key Logs to Detect Lateral Movement in AD

* absolutnie nic ciekawego

### Deception: Tricking the Adversary

* Super pomysłem jest wykorzystanie kanarka w formie hasza wstrzykniętego do procesu lsass w celu wykrycia próby wykorzystania zdumpowanych poświadczeń. Ta metoda została zaimplementowana w frameworku Empire[^12]
* Można również próbować oszukać Bloodhounda poprzez tworzenie fałszywych relacji, ale wygląda to na trudne do ogarnięcia w rzeczywistym środowisku.
* ResponderGuard potrafi wysyłać fałszywe hasze, żeby skusić respondera do tego aby je wykorzystał i w ten sposób wykryć podejrzaną aktywność

# Action on Objectives, Threat Hunting, and Incident Response

## Domain Dominance

### Domination the AD: Basic Strategies

### Golden Ticket, Skeleton Key, DCSync, and DCShadow

* Domyślnym hasłem w ataku Skeleton Key implementowanym przez mimikatza jest `mimikatz`
* Atak DCShadow pozwala symulować działanie kontrolera domeny i w ten sposób wymusić zmianę w AD (np. zmienić hasło). Ten atak jest bardzo skryty - mało logów - czyli nie widać jaka zmiana została scommitowana
* Dominacja w AD poprzez wpływanie na polityki GPO daje bardzo duży wachlarz możliwości: 1. można nadać komuś SeDebugPrivilege, albo zainstalować zadanie harmonogramu w całym środowisku (uruchomić w ten sposób plik wykonywalny)

### Detecting Domain Dominance

* Dobrze monitorować EventID: 4728 (dodanie użytkownika do grupy)
* Skeleton Key wymaga wspierania przez Kerberos schematu RC4_hmac... a to oznacza, że warto monitorować uwierzytelnienia w oparciu o RC4 i ewentualnie to czy jest ono obsługiwane (jeśli nie powinno być)
* Golden Ticket: warto rotować klucze krbtgt raz na jakiś czas. Można monitorować EventID: 4769 w poszukiwaniu pewnych anomalii ale jest to dość kłopotliwe
* Teoretycznie można również monitorować końcówki w poszukiwaniu ticketów kerberosowych wystawionych z bardzo długą datą ważności (np. przy pomocy polecenia `klist`) i w ten sposób wykrywać ataki typu Golden Ticket
* DCSynca warto wykrywać poprzez monitorowanie ruchu sieciowego (replikacje powinny odbywać się TYLKO pomiędzy kontrolerami domeny)
* DCShadow również może być wykryty poprzez monitorowanie ruchu sieciowego (replikacja), za to zmiany wprowadzone przez DCShadow są trudne do wychwycenia. Poza tym można jeszcze monitorować eventy 5137 & 5141 następujące po sobie (utworzenie i usunięcie kontrolera domeny)
* Wykrywanie modyfikacji w GPO wymaga włączenia audytowania - `Audit Detailed Directory Service Replication` co sprawi, że w SECURITY logu zaczną pojawiać się odpowiednie eventy

## Data Exfiltration

### Common Exfiltration Strategies

* Powershell pozwala rozproszyć zadania na zdalne komputery i można to wykorzystać do szukania wrażliwych zbiorów danych `Invoke-Command -ComputerName <name> { cmd }`
* Można wykorzystać Yara lub ClamAV do wyszukiwania interesujących zbiorów
* Można się skupić na wykrywaniu - np. EventID:5140 "A network share object was accessed", ale również audit failures
* Pewne dane powinny być offline, mogą być przechowywane cyfrowo lecz odłączone od sieci
* Blokowanie exfiltracji jest szalenie trudne i być może niepraktyczne
* Szalenie kreatywny sposób exfiltracji - dołączenie danych do próbki malware'u, które po wysłaniu do sandboxa chmury AV odeśle te dane z powrotem do przestępcy
* DLP raczej zapobiega przypadkowym wyciekom, średnio radzi sobie ze zmotywowanym adwersarzem
* Bardzo ciekawym sposobem wykrywania exfiltracji jest tworzenie profilu download-upload (stosunku tych wartości). W ten sposób można wykrywać anomalie m. im. eksfiltracje
* Należy pamiętać o wykrywaniu "ukrytych kanałów informacji" - poprzez np. dużą ilość TXT, wysoką entropie DNS (rozwiązywanych nazw), dużą ilość żądań, długie nazwy, base64 w żądaniach itp.

## Leveraging Threat Intelligence

### Defining Threat Intelligence

* Intel można kupić, uzyskać poprzez wymianę lub wytworzyć samemu - najlepiej dążyć do kombinacji tych 3 wariantów 

## Threat Hunting and Incident Response

### Proactive Threat Hunting Strategies

* nic ciekawego

### Incident Response Process

* Przywołąnie pętli OODA w kontekście obsługi incydentu ma sens, ponieważ przeciwnik jest człowiekiem i jego działania również wymagają OODA - kluczem jest wykonywać tą pętle szybciej niż adwersarz
* Trzy elementy do przygotowania przed IRem - ir plan, plan komunikacji, dokumentacja

# Przypisy

[^1]: [NIST Checlist](https://ncp.nist.gov/repository)
[^2]: [Ansible Hardening Role](https://github.com/openstack/ansible-hardening)
[^3]: Spotting the Adversary with Windows Event Log Monitoring / [Event Forwarding Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance)
[^4]: [Events to Monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
[^5]: Malware Archeology - [Cheat-Sheets](https://www.malwarearchaeology.com/cheat-sheets)
[^6]: [Endpoint detection Superpowers on the cheap](https://medium.com/@olafhartong/endpoint-detection-superpowers-on-the-cheap-part-1-e9c28201ac47)
[^7]: [Fenrir](https://github.com/Orange-Cyberdefense/fenrir-ocd), [NAC bypass cheatsheet](https://redteam.coffee/woot/nac-bypass-cheatsheet)
[^8]: [Malware-Traffic-Analysis.net](https://malware-traffic-analysis.net)
[^9]: [Microsoft Threat Modelling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool)
[^10]: [The C2Matrix](https://www.thec2matrix.com)
[^11]: [github hfiref0x/UACME](https://github.com/hfiref0x/UACME)
[^12]: [New-HoneyHash.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/management/New-HoneyHash.ps1)
