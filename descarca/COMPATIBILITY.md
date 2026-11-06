# Compatibilitate Android

Pagina de instalare a fost mutată la https://caiuspoputa-debug.github.io/trust-mc-apps/descarca/.

Păstrați manifest.json și APK-ul criptat în această adresă GitHub: versiunile Android existente folosesc o listă strictă de URL-uri din /trust-mc-romania/descarca/. Actualizați-le împreună cu noul depozit la fiecare release, până când toate versiunile folosite au un updater migrat. Nu transformați acest GitHub Pages în redirect global către domeniul oficial și nu eliminați fișierele înainte de migrarea clienților.

La următoarea versiune Android, BASE și verificarea URL-ului din ApkUpdateEngine.java trebuie actualizate la /trust-mc-apps/descarca/, apoi aplicația trebuie recompilată și semnată cu aceeași cheie.
