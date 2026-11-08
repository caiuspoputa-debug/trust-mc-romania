(function (root) {
  'use strict';
  var ITERATIONS = 600000;
  var MAX_APK = 40 * 1024 * 1024;

  function failure(code) { var error = new Error(code); error.code = code; return error; }
  function utf8(text) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(text);
    var encoded = unescape(encodeURIComponent(text)), result = new Uint8Array(encoded.length), i;
    for (i = 0; i < encoded.length; i++) result[i] = encoded.charCodeAt(i);
    return result;
  }
  function hex(bytes) {
    var result = '', i, value;
    bytes = new Uint8Array(bytes);
    for (i = 0; i < bytes.length; i++) { value = bytes[i].toString(16); result += value.length === 1 ? '0' + value : value; }
    return result;
  }
  function unhex(value) {
    var result = new Uint8Array(value.length / 2), i;
    for (i = 0; i < result.length; i++) result[i] = parseInt(value.substr(i * 2, 2), 16);
    return result;
  }
  function validate(m) {
    if (!m || m.schema !== 1 || m.packageName !== 'ro.trustmc.nativeapp' ||
        typeof m.version !== 'string' || !/^\d+\.\d+(?:\.\d+)?$/.test(m.version) ||
        typeof m.fileName !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{1,100}\.apk$/.test(m.fileName) ||
        typeof m.apkBytes !== 'number' || m.apkBytes % 1 !== 0 || m.apkBytes < 1024 || m.apkBytes > MAX_APK ||
        typeof m.apkSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(m.apkSha256) ||
        typeof m.minAndroid !== 'string' || !/^\d+(?:\.\d+)?$/.test(m.minAndroid) ||
        !m.kdf || m.kdf.name !== 'PBKDF2' || m.kdf.hash !== 'SHA-256' || m.kdf.iterations !== ITERATIONS ||
        typeof m.kdf.salt !== 'string' || !/^[a-f0-9]{32}$/.test(m.kdf.salt) ||
        !m.cipher || m.cipher.name !== 'AES-GCM' || m.cipher.keyBits !== 256 || m.cipher.tagBits !== 128 ||
        typeof m.cipher.iv !== 'string' || !/^[a-f0-9]{24}$/.test(m.cipher.iv) ||
        typeof m.cipher.file !== 'string' || !/^TrustMC-[0-9.]+-[a-f0-9]{16}\.apk\.enc$/.test(m.cipher.file) ||
        typeof m.cipher.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(m.cipher.sha256) ||
        m.cipher.bytes !== m.apkBytes + 16) throw failure('MANIFEST');
    return m;
  }
  function aad(m) {
    return utf8(JSON.stringify(['TRUST-MC-APK', m.schema, m.packageName, m.fileName, m.version,
      m.apkBytes, m.apkSha256, m.minAndroid, m.kdf.salt, m.kdf.iterations, m.cipher.iv, m.cipher.file]));
  }
  function decryptApk(m, encrypted, password, cryptoApi) {
    var api = cryptoApi || root.crypto, keyMaterial, passwordBytes;
    try {
      validate(m);
      if (!api || !api.subtle) throw failure('UNSUPPORTED');
      if (typeof password !== 'string' || password.length === 0 || password.length > 1024) throw failure('PASSWORD');
      if (!encrypted || encrypted.byteLength !== m.cipher.bytes) throw failure('INTEGRITY');
      passwordBytes = utf8(password);
    } catch (error) { return Promise.reject(error); }
    return api.subtle.digest('SHA-256', encrypted).then(function (digest) {
      if (hex(digest) !== m.cipher.sha256) throw failure('INTEGRITY');
      return api.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
    }).then(function (material) {
      keyMaterial = material; passwordBytes.fill ? passwordBytes.fill(0) : null;
      return api.subtle.deriveKey({name: 'PBKDF2', salt: unhex(m.kdf.salt), iterations: ITERATIONS, hash: 'SHA-256'},
        keyMaterial, {name: 'AES-GCM', length: 256}, false, ['decrypt']);
    }).then(function (key) {
      return api.subtle.decrypt({name: 'AES-GCM', iv: unhex(m.cipher.iv), tagLength: 128, additionalData: aad(m)}, key, encrypted)
        .catch(function () { throw failure('PASSWORD'); });
    }).then(function (plain) {
      if (plain.byteLength !== m.apkBytes) throw failure('INTEGRITY');
      return api.subtle.digest('SHA-256', plain).then(function (digest) {
        if (hex(digest) !== m.apkSha256) throw failure('INTEGRITY');
        return plain;
      });
    }).catch(function (error) {
      if (passwordBytes && passwordBytes.fill) passwordBytes.fill(0);
      throw error;
    });
  }
  function request(url, binary) {
    return new Promise(function (resolve, reject) {
      var xhr = new XMLHttpRequest();
      xhr.open('GET', url, true); xhr.timeout = 90000;
      if (binary) xhr.responseType = 'arraybuffer';
      xhr.onload = function () {
        if (xhr.status < 200 || xhr.status >= 300) { reject(failure('NETWORK')); return; }
        if (binary) { resolve(xhr.response); return; }
        try { resolve(JSON.parse(xhr.responseText)); } catch (error) { reject(failure('MANIFEST')); }
      };
      xhr.onerror = xhr.ontimeout = xhr.onabort = function () { reject(failure('NETWORK')); };
      xhr.send();
    });
  }
  var exported = {validate: validate, aad: aad, decryptApk: decryptApk, utf8: utf8, hex: hex, unhex: unhex};
  if (typeof module === 'object' && module.exports) module.exports = exported;
  else root.TrustDownloadCrypto = exported;
  if (typeof document === 'undefined') return;

  // UI is deliberately separate from the unchanged authenticated APK format above.
  var languages = ['ro', 'de', 'pl', 'nl', 'en'];
  var languageNames = {ro:'Română',de:'Deutsch',pl:'Polski',nl:'Nederlands (België)',en:'English'};
  var labels = {ro:'RO',de:'DE',pl:'PL',nl:'BE',en:'EN'};
  var messages = {
    title:['Aplicația TRUST MC — Android și iPhone','TRUST MC App — Android und iPhone','Aplikacja TRUST MC — Android i iPhone','TRUST MC-app — Android en iPhone','TRUST MC app — Android and iPhone'],
    meta:['TRUST MC pentru Android și iPhone. Aceleași conturi, calendare și date ale clubului.','TRUST MC für Android und iPhone. Dieselben Konten, Kalender und Clubdaten.','TRUST MC na Androida i iPhone’a. Te same konta, kalendarze i dane klubu.','TRUST MC voor Android en iPhone. Dezelfde accounts, kalenders en clubgegevens.','TRUST MC for Android and iPhone. The same accounts, calendars and club data.'],
    skip:['Mergi la descărcare','Zum Download','Przejdź do pobierania','Naar de download','Skip to download'],
    back:['Înapoi la site','Zurück zur Website','Powrót do strony','Terug naar de website','Back to the website'],
    language:['LIMBA PAGINII','SPRACHE DER SEITE','JĘZYK STRONY','TAAL VAN DE PAGINA','PAGE LANGUAGE'],
    eyebrow:['FAMILIA TRUST. ORIUNDE.','DIE TRUST-FAMILIE. ÜBERALL.','RODZINA TRUST. WSZĘDZIE.','DE TRUST-FAMILIE. OVERAL.','THE TRUST FAMILY. EVERYWHERE.'],
    headline:['PE TELEFONUL TĂU.','AUF DEINEM HANDY.','NA TWOIM TELEFONIE.','OP JE TELEFOON.','ON YOUR PHONE.'],
    intro:['Android sau iPhone. Aceeași familie, aceleași conturi și aceleași calendare sincronizate.','Android oder iPhone. Dieselbe Familie, dieselben Konten und synchronisierten Kalender.','Android lub iPhone. Ta sama rodzina, te same konta i zsynchronizowane kalendarze.','Android of iPhone. Dezelfde familie, dezelfde accounts en gesynchroniseerde kalenders.','Android or iPhone. The same family, accounts and synchronized calendars.'],
    app:['APLICAȚIA TRUST MC','DIE TRUST MC APP','APLIKACJA TRUST MC','DE TRUST MC-APP','THE TRUST MC APP'],
    choose:['ALEGE TELEFONUL','WÄHLE DEIN HANDY','WYBIERZ TELEFON','KIES JE TELEFOON','CHOOSE YOUR PHONE'],
    androidSub:['Aplicație APK','APK-App','Aplikacja APK','APK-app','APK app'],
    iphoneSub:['Aplicație web','Web-App','Aplikacja internetowa','Webapp','Web app'],
    android_heading:['DESCARCĂ APK','APK HERUNTERLADEN','POBIERZ APK','APK DOWNLOADEN','DOWNLOAD APK'],
    iphone_heading:['DESCHIDE PE IPHONE','AUF DEM IPHONE ÖFFNEN','OTWÓRZ NA IPHONIE','OPENEN OP IPHONE','OPEN ON IPHONE'],
    android_description:['Introdu parola primită. APK-ul se descarcă automat după verificare.','Gib das erhaltene Passwort ein. Nach der Prüfung startet der APK-Download automatisch.','Wpisz otrzymane hasło. Pobieranie APK rozpocznie się automatycznie po weryfikacji.','Voer het ontvangen wachtwoord in. Na controle start de APK-download automatisch.','Enter the password you received. The APK downloads automatically after verification.'],
    iphone_description:['Introdu aceeași parolă de acces. Se deschide direct aplicația web pentru iPhone.','Gib dasselbe Zugangspasswort ein. Die Web-App für das iPhone wird direkt geöffnet.','Wpisz to samo hasło dostępu. Aplikacja internetowa dla iPhone’a otworzy się bezpośrednio.','Voer hetzelfde toegangswachtwoord in. De webapp voor iPhone opent meteen.','Enter the same access password. The iPhone web app opens directly.'],
    iphoneSummary:['Se deschide aplicația web TRUST MC. În Safari o poți adăuga pe ecranul principal. Contul și datele sunt comune cu Android.','Die TRUST MC Web-App wird geöffnet. In Safari kannst du sie zum Home-Bildschirm hinzufügen. Konto und Daten sind mit Android identisch.','Otworzy się aplikacja internetowa TRUST MC. W Safari możesz dodać ją do ekranu początkowego. Konto i dane są wspólne z Androidem.','De TRUST MC-webapp opent. In Safari kun je ze op het beginscherm zetten. Je account en gegevens zijn dezelfde als op Android.','The TRUST MC web app opens. In Safari you can add it to your Home Screen. It shares your account and data with Android.'],
    iphoneCardTitle:['INSTALARE PE IPHONE','AUF DEM IPHONE INSTALLIEREN','INSTALACJA NA IPHONIE','INSTALLEREN OP IPHONE','INSTALL ON IPHONE'],
    iphoneCard1:['Deschide aplicația TRUST MC în Safari.','Öffne die TRUST MC-App in Safari.','Otwórz aplikację TRUST MC w Safari.','Open de TRUST MC-app in Safari.','Open the TRUST MC app in Safari.'],
    iphoneCard2:['Apasă Partajare — pătratul cu săgeata în sus.','Tippe auf „Teilen“ — das Quadrat mit dem Pfeil nach oben.','Naciśnij „Udostępnij” — kwadrat ze strzałką w górę.','Tik op ‘Deel’ — het vierkant met de pijl omhoog.','Tap Share — the square with the upward arrow.'],
    iphoneCard3:['Alege „Adaugă pe ecranul principal” și confirmă „Adaugă”.','Wähle „Zum Home-Bildschirm“ und bestätige mit „Hinzufügen“.','Wybierz „Do ekranu początkowego” i potwierdź „Dodaj”.','Kies ‘Zet op beginscherm’ en bevestig met ‘Voeg toe’.','Choose “Add to Home Screen” and confirm “Add”.'],
    iphoneCardDone:['Pictograma TRUST MC apare pe ecran. De acum, deschide aplicația de acolo, conectează-te și activează notificările din meniul aplicației.','Das TRUST MC-Symbol erscheint auf dem Home-Bildschirm. Öffne die App künftig dort, melde dich an und aktiviere Benachrichtigungen im App-Menü.','Ikona TRUST MC pojawi się na ekranie. Od teraz otwieraj aplikację stamtąd, zaloguj się i włącz powiadomienia w menu aplikacji.','Het TRUST MC-pictogram verschijnt op je beginscherm. Open de app voortaan daar, meld je aan en activeer meldingen in het appmenu.','The TRUST MC icon appears on your Home Screen. From now on, open the app there, sign in and enable notifications from the app menu.'],
    version:['VERSIUNE','VERSION','WERSJA','VERSIE','VERSION'],
    size:['DIMENSIUNE','GRÖSSE','ROZMIAR','GROOTTE','SIZE'],
    password:['Parola de acces','Zugangspasswort','Hasło dostępu','Toegangswachtwoord','Access password'],
    show:['Arată','Anzeigen','Pokaż','Tonen','Show'],hide:['Ascunde','Verbergen','Ukryj','Verbergen','Hide'],
    showPassword:['Arată parola','Passwort anzeigen','Pokaż hasło','Wachtwoord tonen','Show password'],hidePassword:['Ascunde parola','Passwort verbergen','Ukryj hasło','Wachtwoord verbergen','Hide password'],
    android_submit:['Descarcă APK','APK herunterladen','Pobierz APK','APK downloaden','Download APK'],
    iphone_submit:['Deschide pe iPhone','Auf dem iPhone öffnen','Otwórz na iPhonie','Openen op iPhone','Open on iPhone'],
    initial:['Parola ți-a fost transmisă separat.','Das Passwort wurde dir separat mitgeteilt.','Hasło zostało przekazane osobno.','Het wachtwoord is apart bezorgd.','The password was provided separately.'],
    fallback:['Dacă descărcarea nu a pornit, apasă aici ↓','Falls der Download nicht startet, hier tippen ↓','Jeśli pobieranie się nie rozpoczęło, naciśnij tutaj ↓','Begint de download niet? Tik dan hier ↓','If the download did not start, tap here ↓'],
    accountNote:['Parola de acces este diferită de parola contului tău de membru TRUST MC.','Das Zugangspasswort ist nicht das Passwort deines TRUST MC-Mitgliedskontos.','Hasło dostępu różni się od hasła do Twojego konta członkowskiego TRUST MC.','Het toegangswachtwoord verschilt van het wachtwoord van je TRUST MC-ledenaccount.','This access password is separate from your TRUST MC member account password.'],
    stepsKicker:['TREI PAȘI. ACEEAȘI FRĂȚIE.','DREI SCHRITTE. DIESELBE BRUDERSCHAFT.','TRZY KROKI. TO SAMO BRATERSTWO.','DRIE STAPPEN. DEZELFDE BROEDERSCHAP.','THREE STEPS. THE SAME BROTHERHOOD.'],
    android_stepsTitle:['INSTALARE PE ANDROID','INSTALLATION AUF ANDROID','INSTALACJA NA ANDROIDZIE','INSTALLEREN OP ANDROID','INSTALL ON ANDROID'],
    iphone_stepsTitle:['CONT ȘI NOTIFICĂRI','KONTO UND BENACHRICHTIGUNGEN','KONTO I POWIADOMIENIA','ACCOUNT EN MELDINGEN','ACCOUNT AND NOTIFICATIONS'],
    android1Title:['DESCARCĂ','HERUNTERLADEN','POBIERZ','DOWNLOADEN','DOWNLOAD'],
    android1:['Introdu parola și apasă „Descarcă APK”. După verificare, descărcarea pornește automat.','Gib das Passwort ein und tippe auf „APK herunterladen“. Nach der Prüfung startet der Download automatisch.','Wpisz hasło i naciśnij „Pobierz APK”. Po weryfikacji pobieranie rozpocznie się automatycznie.','Voer het wachtwoord in en tik op ‘APK downloaden’. Na controle start de download automatisch.','Enter the password and tap “Download APK”. After verification, the download starts automatically.'],
    android2Title:['INSTALEAZĂ','INSTALLIEREN','ZAINSTALUJ','INSTALLEREN','INSTALL'],
    android2:['Deschide fișierul APK. Dacă Android îți cere, permite instalarea din browserul folosit.','Öffne die APK-Datei. Erlaube bei Bedarf die Installation über den verwendeten Browser.','Otwórz plik APK. Jeśli Android o to poprosi, zezwól na instalację z używanej przeglądarki.','Open het APK-bestand. Sta de installatie vanuit je browser toe als Android daarom vraagt.','Open the APK file. If Android asks, allow installation from the browser you used.'],
    android3Title:['INTRĂ ÎN CONT','ANMELDEN','ZALOGUJ SIĘ','AANMELDEN','SIGN IN'],
    android3:['Deschide TRUST MC și autentifică-te. Conturile noi sunt aprobate de un administrator.','Öffne TRUST MC und melde dich an. Neue Konten werden von einem Administrator freigegeben.','Otwórz TRUST MC i zaloguj się. Nowe konta zatwierdza administrator.','Open TRUST MC en meld je aan. Nieuwe accounts worden goedgekeurd door een beheerder.','Open TRUST MC and sign in. New accounts require an administrator’s approval.'],
    iphone1Title:['DESCHIDE','ÖFFNEN','OTWÓRZ','OPENEN','OPEN'],
    iphone1:['Alege iPhone, introdu parola și apasă „Deschide pe iPhone”. Se deschide aplicația web.','Wähle iPhone, gib das Passwort ein und tippe auf „Auf dem iPhone öffnen“. Die Web-App wird geöffnet.','Wybierz iPhone, wpisz hasło i naciśnij „Otwórz na iPhonie”. Otworzy się aplikacja internetowa.','Kies iPhone, voer het wachtwoord in en tik op ‘Openen op iPhone’. De webapp opent.','Choose iPhone, enter the password and tap “Open on iPhone”. The web app opens.'],
    iphone2Title:['ADAUGĂ PE ECRAN','ZUM HOME-BILDSCHIRM','DODAJ DO EKRANU','OP BEGINSCHERM','ADD TO HOME SCREEN'],
    iphone2:['În Safari: Partajare → Adaugă pe ecranul principal. Confirmă „Adaugă”, apoi deschide pictograma TRUST MC.','In Safari: Teilen → Zum Home-Bildschirm. Bestätige „Hinzufügen“ und öffne danach das TRUST MC-Symbol.','W Safari: Udostępnij → Do ekranu początkowego. Potwierdź „Dodaj”, a następnie otwórz ikonę TRUST MC.','In Safari: Deel → Zet op beginscherm. Bevestig ‘Voeg toe’ en open daarna het TRUST MC-pictogram.','In Safari: Share → Add to Home Screen. Confirm “Add”, then open the TRUST MC icon.'],
    iphone3Title:['CONECTEAZĂ-TE','ANMELDEN','ZALOGUJ SIĘ','AANMELDEN','SIGN IN'],
    iphone3:['Folosește același cont TRUST MC. Activează notificările din aplicația deschisă de pe ecranul principal.','Nutze dasselbe TRUST MC-Konto. Aktiviere Benachrichtigungen in der über den Home-Bildschirm geöffneten App.','Użyj tego samego konta TRUST MC. Włącz powiadomienia w aplikacji otwartej z ekranu początkowego.','Gebruik hetzelfde TRUST MC-account. Activeer meldingen in de app die je vanaf het beginscherm opent.','Use the same TRUST MC account. Enable notifications from the app opened from your Home Screen.'],
    androidNote:['Ai deja aplicația Android? Instalează actualizarea peste versiunea existentă, fără dezinstalare, pentru a păstra datele locale.','Android-App bereits installiert? Installiere das Update über die vorhandene Version, ohne sie zu deinstallieren, damit lokale Daten erhalten bleiben.','Masz już aplikację na Androidzie? Zainstaluj aktualizację na istniejącej wersji bez odinstalowywania, aby zachować dane lokalne.','Heb je de Android-app al? Installeer de update over de bestaande versie zonder die te verwijderen, zodat lokale gegevens behouden blijven.','Already have the Android app? Install the update over the existing version without uninstalling to keep local data.'],
    iphoneNote:['Folosește același cont și aceleași date ca pe Android. Notificările Web Push necesită iOS 16.4 sau mai nou și aplicația adăugată pe ecranul principal.','Nutze dasselbe Konto und dieselben Daten wie auf Android. Web-Push erfordert iOS 16.4 oder neuer und die App auf dem Home-Bildschirm.','Użyj tego samego konta i danych co na Androidzie. Web Push wymaga iOS 16.4 lub nowszego i aplikacji dodanej do ekranu początkowego.','Gebruik hetzelfde account en dezelfde gegevens als op Android. Web Push vereist iOS 16.4 of nieuwer en de app op het beginscherm.','Use the same account and data as on Android. Web Push requires iOS 16.4 or later and the app added to your Home Screen.'],
    sharedTitle:['ACELAȘI CONT. ACELEAȘI DATE.','DASSELBE KONTO. DIESELBEN DATEN.','TO SAMO KONTO. TE SAME DANE.','HETZELFDE ACCOUNT. DEZELFDE GEGEVENS.','THE SAME ACCOUNT. THE SAME DATA.'],
    sharedText:['Evenimentele, mesajele, invitațiile și drepturile de acces folosesc datele comune ale clubului. Modificările se sincronizează prin internet pe Android și iPhone.','Veranstaltungen, Nachrichten, Einladungen und Zugriffsrechte nutzen die gemeinsamen Clubdaten. Änderungen werden über das Internet auf Android und iPhone synchronisiert.','Wydarzenia, wiadomości, zaproszenia i uprawnienia korzystają ze wspólnych danych klubu. Zmiany synchronizują się przez internet na Androidzie i iPhonie.','Evenementen, berichten, uitnodigingen en toegangsrechten gebruiken de gemeenschappelijke clubgegevens. Wijzigingen synchroniseren via internet op Android en iPhone.','Events, messages, invitations and access permissions use the club’s shared data. Changes synchronize over the internet on Android and iPhone.'],
    credit:['Realizat cu sprijinul TRUST MC Bocșa','Mit Unterstützung von TRUST MC Bocșa','Zrealizowano przy wsparciu TRUST MC Bocșa','Met steun van TRUST MC Bocșa','Made with the support of TRUST MC Bocșa'],
    busyAndroid:['Se pregătește APK-ul…','APK wird vorbereitet…','Przygotowywanie APK…','APK wordt voorbereid…','Preparing APK…'],
    busyIphone:['Se deschide aplicația…','App wird geöffnet…','Otwieranie aplikacji…','App wordt geopend…','Opening the app…'],
    loading:['Se pregătește descărcarea. Poate dura câteva secunde pe un telefon mai vechi.','Der Download wird vorbereitet. Auf älteren Handys kann dies einige Sekunden dauern.','Przygotowywanie pobierania. Na starszym telefonie może to potrwać kilka sekund.','De download wordt voorbereid. Op oudere telefoons kan dit enkele seconden duren.','Preparing your download. This may take a few seconds on an older phone.'],
    opening:['Se verifică accesul și se deschide aplicația pentru iPhone.','Der Zugang wird geprüft und die iPhone-App geöffnet.','Sprawdzanie dostępu i otwieranie aplikacji dla iPhone’a.','De toegang wordt gecontroleerd en de iPhone-app opent.','Checking access and opening the iPhone app.'],
    started:['Descărcarea APK a pornit. Dacă browserul nu a salvat fișierul, folosește linkul de mai jos.','Der APK-Download wurde gestartet. Falls der Browser die Datei nicht gespeichert hat, nutze den Link unten.','Pobieranie APK rozpoczęte. Jeśli przeglądarka nie zapisała pliku, użyj linku poniżej.','De APK-download is gestart. Slaat de browser het bestand niet op? Gebruik dan de link hieronder.','The APK download has started. If your browser did not save it, use the link below.'],
    missing:['Introdu parola primită pentru descărcare.','Gib das erhaltene Zugangspasswort ein.','Wpisz otrzymane hasło dostępu.','Voer het ontvangen toegangswachtwoord in.','Enter the access password you received.'],
    wrong:['Parola nu este corectă. Încearcă din nou.','Das Passwort ist nicht korrekt. Versuche es erneut.','Hasło jest nieprawidłowe. Spróbuj ponownie.','Het wachtwoord is niet juist. Probeer opnieuw.','The password is incorrect. Try again.'],
    network:['Descărcarea nu a reușit. Verifică internetul și încearcă din nou.','Der Download ist fehlgeschlagen. Prüfe die Internetverbindung und versuche es erneut.','Pobieranie nie powiodło się. Sprawdź połączenie z internetem i spróbuj ponownie.','De download is mislukt. Controleer je internetverbinding en probeer opnieuw.','Download failed. Check your internet connection and try again.'],
    integrity:['Fișierul nu a putut fi verificat. Reîncarcă pagina și încearcă din nou.','Die Datei konnte nicht geprüft werden. Lade die Seite neu und versuche es erneut.','Nie udało się zweryfikować pliku. Odśwież stronę i spróbuj ponownie.','Het bestand kon niet worden gecontroleerd. Herlaad de pagina en probeer opnieuw.','The file could not be verified. Reload the page and try again.'],
    manifestError:['Informațiile descărcării nu au putut fi încărcate. Verifică internetul și încearcă din nou.','Die Downloadinformationen konnten nicht geladen werden. Prüfe die Internetverbindung und versuche es erneut.','Nie udało się wczytać informacji o pobieraniu. Sprawdź internet i spróbuj ponownie.','De downloadgegevens konden niet worden geladen. Controleer je internetverbinding en probeer opnieuw.','Download information could not be loaded. Check your connection and try again.'],
    unsupported:['Pentru descărcare, deschide această pagină prin HTTPS într-un browser Chrome, Firefox sau Edge actualizat.','Öffne diese Seite zum Herunterladen per HTTPS in einem aktuellen Chrome-, Firefox- oder Edge-Browser.','Aby pobrać plik, otwórz stronę przez HTTPS w aktualnej przeglądarce Chrome, Firefox lub Edge.','Open deze pagina via HTTPS in een bijgewerkte Chrome-, Firefox- of Edge-browser om te downloaden.','To download, open this page over HTTPS in an up-to-date Chrome, Firefox or Edge browser.'],
    restored:['Introdu parola pentru a pregăti din nou descărcarea.','Gib das Passwort ein, um den Download erneut vorzubereiten.','Wpisz hasło, aby ponownie przygotować pobieranie.','Voer het wachtwoord in om de download opnieuw voor te bereiden.','Enter the password to prepare the download again.']
  };
  var language = 'ro', platform = 'android', lastStatus = 'initial', lastError = false;
  function normalize(value) { value = String(value || '').toLowerCase().split(/[-_]/)[0];return value === 'be' ? 'nl' : languages.indexOf(value) >= 0 ? value : 'ro'; }
  try { language = normalize(root.localStorage.getItem('trust-download-language') || 'ro'); } catch (ignore) {}
  if (root.location && /[?&]lang=([a-z_-]+)/i.test(root.location.search || '')) language = normalize(RegExp.$1);
  if (root.navigator && /iPhone|iPad|iPod/i.test(root.navigator.userAgent || '')) platform = 'iphone';
  if (root.location && /[?&]platform=(android|iphone)/i.test(root.location.search || '')) platform = RegExp.$1.toLowerCase();
  function text(key) { return messages[key] ? messages[key][languages.indexOf(language)] : key; }
  var form = document.getElementById('download-form'), passwordInput = document.getElementById('download-password');
  var button = document.getElementById('download-button'), status = document.getElementById('download-status');
  var spinner = document.getElementById('download-spinner'), toggle = document.getElementById('password-toggle');
  var ready = document.getElementById('ready-download'), objectUrl = '', busy = false, generation = 0;
  if (!form || !passwordInput || !button || !status || !ready) return;
  var buttonLabel = typeof button.querySelector === 'function' ? button.querySelector('span') : null;
  if (!buttonLabel) buttonLabel = button;
  passwordInput.value = ''; passwordInput.type = 'password';
  function each(selector, callback) { if (typeof document.querySelectorAll === 'function') Array.prototype.forEach.call(document.querySelectorAll(selector), callback); }
  function say(key, error) { lastStatus = key;lastError = !!error;status.textContent = text(key);status.className = error ? 'download-status is-error' : 'download-status'; }
  function updateToggle() { if (!toggle) return;var visible = passwordInput.type !== 'password';toggle.textContent = text(visible ? 'hide' : 'show');toggle.setAttribute('aria-label', text(visible ? 'hidePassword' : 'showPassword'));toggle.setAttribute('aria-pressed', visible ? 'true' : 'false'); }
  function renderLanguages() {
    var target = document.getElementById('language-switcher');if (!target || typeof document.createElement !== 'function') return;
    while (target.firstChild) target.removeChild(target.firstChild);
    target.setAttribute('aria-label', text('language'));
    [language].concat(languages.filter(function (code) { return code !== language; })).forEach(function (code) {
      var choice = document.createElement('button');choice.type = 'button';choice.textContent = labels[code];choice.lang = code;choice.disabled = busy;
      choice.setAttribute('aria-label', languageNames[code]);choice.setAttribute('aria-pressed', code === language ? 'true' : 'false');choice.setAttribute('data-language', code);
      choice.addEventListener('click', function () { if (busy) return;language = code;try { root.localStorage.setItem('trust-download-language', code); } catch (ignore) {}applyLanguage(); });target.appendChild(choice);
    });
  }
  function applyLanguage() {
    if (document.documentElement) document.documentElement.lang = language;document.title = text('title');
    each('[data-i18n]', function (node) { node.textContent = text(node.getAttribute('data-i18n')); });
    each('[data-i18n-content]', function (node) { node.setAttribute('content', text(node.getAttribute('data-i18n-content'))); });
    each('[data-i18n-platform]', function (node) { node.textContent = text(platform + '_' + node.getAttribute('data-i18n-platform')); });
    var code = document.getElementById('install-language');if (code) code.value = language;
    buttonLabel.textContent = busy ? text(platform === 'iphone' ? 'busyIphone' : 'busyAndroid') : text(platform + '_submit');
    updateToggle();say(lastStatus, lastError);renderLanguages();
    var size = document.getElementById('apk-size');if (size && loadedManifest) size.textContent = (loadedManifest.apkBytes / 1000000).toFixed(1).replace('.', language === 'en' ? '.' : ',') + ' MB';
  }
  function loading(value, keepInput) {
    busy = value;button.disabled = value || platform === 'android' && !compatible();passwordInput.disabled = value && !keepInput;
    if (toggle) toggle.disabled = value;if (spinner) spinner.hidden = !value;button.setAttribute('aria-busy', value ? 'true' : 'false');
    each('[data-platform],[data-language]', function (node) { node.disabled = value; });
    buttonLabel.textContent = value ? text(platform === 'iphone' ? 'busyIphone' : 'busyAndroid') : text(platform + '_submit');
  }
  function revoke() { if (objectUrl) { URL.revokeObjectURL(objectUrl);objectUrl = ''; }ready.hidden = true;ready.removeAttribute('href'); }
  function compatible() { return !!(root.crypto && root.crypto.subtle && root.Promise && root.XMLHttpRequest && root.Blob && root.URL && root.URL.createObjectURL); }
  function selectPlatform(value) {
    if (busy) return;platform = value === 'iphone' ? 'iphone' : 'android';generation++;revoke();lastStatus = 'initial';lastError = false;passwordInput.type = 'password';
    form.action = platform === 'iphone' ? 'https://trust-mc-web.peachywave5.chatgpt.site/api/install/unlock' : '#';form.method = 'post';
    var label = document.getElementById('platform-label');if (label) label.textContent = platform === 'iphone' ? 'iPhone' : 'Android';
    ['android-details','android-steps','android-note','android-steps-kicker'].forEach(function (id) { var node = document.getElementById(id);if (node) node.hidden = platform !== 'android'; });
    ['iphone-install-card','iphone-steps','iphone-note'].forEach(function (id) { var node = document.getElementById(id);if (node) node.hidden = platform !== 'iphone'; });
    each('[data-platform]', function (node) { node.setAttribute('aria-pressed', node.getAttribute('data-platform') === platform ? 'true' : 'false'); });
    loading(false);if (platform === 'android' && !compatible()) { lastStatus = 'unsupported';lastError = true; }applyLanguage();
  }
  each('[data-platform]', function (node) { node.addEventListener('click', function () { selectPlatform(node.getAttribute('data-platform')); }); });
  if (toggle) toggle.addEventListener('click', function () { passwordInput.type = passwordInput.type === 'password' ? 'text' : 'password';updateToggle();passwordInput.focus(); });
  root.addEventListener('pagehide', function () { generation++;passwordInput.value = '';passwordInput.type = 'password';revoke(); });
  root.addEventListener('pageshow', function (event) { passwordInput.value = '';if (event.persisted) { loading(false);say('restored', false); } });
  var manifestPromise, loadedManifest;
  function manifest() { if (!manifestPromise) manifestPromise = request('manifest.json?t=' + Date.now(), false).then(validate).catch(function (error) { manifestPromise = null;throw error; });return manifestPromise; }
  selectPlatform(platform);
  if (compatible()) manifest().then(function (m) {
    loadedManifest = m;var version = document.getElementById('apk-version'), size = document.getElementById('apk-size'), android = document.getElementById('apk-min-android');
    if (version) version.textContent = m.version;if (size) size.textContent = (m.apkBytes / 1000000).toFixed(1).replace('.', language === 'en' ? '.' : ',') + ' MB';if (android) android.textContent = m.minAndroid + '+';
  }).catch(function () { if (platform === 'android') say('manifestError', true); });
  form.addEventListener('submit', function (event) {
    if (busy) { event.preventDefault();return; }
    var password = passwordInput.value;
    if (!password || password.length > 1024) { event.preventDefault();say('missing', true);passwordInput.focus();return; }
    if (platform === 'iphone') {
      // A normal form POST avoids putting the password in a URL or JavaScript storage.
      // The input must remain enabled until the browser serializes the POST body.
      loading(true, true);say('opening', false);return;
    }
    event.preventDefault();if (!compatible()) return;
    var current = ++generation, focusPassword = false;
    revoke();loading(true);say('loading', false);
    manifest().then(function (m) {
      if (current !== generation) throw failure('CANCELLED');
      return request(m.cipher.file, true).then(function (encrypted) {
        var operation = decryptApk(m, encrypted, password, root.crypto);password = '';passwordInput.value = '';passwordInput.type = 'password';updateToggle();
        return operation.then(function (plain) {
          if (current !== generation) throw failure('CANCELLED');
          objectUrl = URL.createObjectURL(new Blob([plain], {type:'application/vnd.android.package-archive'}));
          ready.href = objectUrl;ready.download = m.fileName;ready.hidden = false;
          // Browsers which allow programmatic downloads start immediately. The visible
          // link remains only as a fallback for a browser that blocks the automatic save.
          if (typeof ready.click === 'function') ready.click();say('started', false);ready.focus();
        });
      });
    }).catch(function (error) {
      password = '';if (current !== generation) return;passwordInput.value = '';
      if (error.code === 'PASSWORD') { say('wrong', true);focusPassword = true; }
      else if (error.code === 'NETWORK') say('network', true);else say('integrity', true);
    }).then(function () { if (current !== generation) return;loading(false);if (focusPassword) passwordInput.focus(); });
  });
}(typeof window !== 'undefined' ? window : this));
