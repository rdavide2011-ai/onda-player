# Onda Player

Player web personale per **Spotify Premium**. Ci accedi con il tuo account Spotify o incolli il link di una playlist, un album o un brano, e lo ascolti dal browser del PC o del telefono. Puoi anche usarlo come telecomando per l'app Spotify.

Non c'è un backend: il login usa OAuth PKCE direttamente dal browser, e salvati, recenti, cronologia, volume e sessione restano nel `localStorage` del dispositivo.

> Serve Spotify Premium. È l'unico modo ufficiale per riprodurre l'audio di Spotify da un sito esterno (Web Playback SDK e i comandi del player della Web API funzionano solo con Premium), ed è per questo che non ci sono pubblicità.

## Funzioni

- Login con Spotify (PKCE, nessun client secret) e rinnovo automatico del token
- Apri un link `open.spotify.com/...` o `spotify:...` di playlist, album, brano o artista; incollandolo nella barra si apre subito
- Le tue playlist, i brani che ti piacciono, la ricerca (brani, playlist, album, artisti)
- Player nel browser (Web Playback SDK) con play/pausa, avanti/indietro, posizione, volume, casuale e ripeti
- **Spotify Connect**: scegli su quale dispositivo suonare (browser, app Spotify sul telefono, PC, casse)
- Comandi dalla schermata di blocco e dalle cuffie (Media Session)
- Salvati, recenti e cronologia brani in `localStorage`, con backup e ripristino in JSON
- PWA installabile sulla schermata Home, con l'interfaccia disponibile anche offline

## Configurazione (una volta sola)

1. Pubblica il sito (vedi sotto) e annota l'indirizzo, es. `https://onda-player.vercel.app/`.
2. Vai su <https://developer.spotify.com/dashboard> → **Create app**.
   - **Redirect URIs**: l'indirizzo del sito, **identico** a quello che la schermata iniziale di Onda ti fa copiare (con la `/` finale).
   - **APIs used**: spunta *Web API* e *Web Playback SDK*.
3. Copia il **Client ID** e incollalo nella schermata iniziale di Onda.
4. Accedi con Spotify.

Note sulle regole di Spotify (Development Mode, febbraio 2026):
- il proprietario dell'app sviluppatore deve avere Premium;
- massimo 5 utenti per app: per usarla con altri account aggiungili in *User Management* nella dashboard;
- Spotify mostra l'elenco dei brani solo per le playlist create da te o di cui sei collaboratore. Le altre (es. quelle editoriali) si possono comunque riprodurre per intero;
- la ricerca restituisce al massimo 10 risultati per pagina.

Spotify non accetta `http://localhost` come redirect. Per provare in locale usa `http://127.0.0.1:PORTA/`.

## Avvio in locale (Windows)

Serve Python, già presente se hai installato Python 3:

```bat
cd onda-player
python -m http.server 5500 --bind 127.0.0.1
```

Apri `http://127.0.0.1:5500/` e aggiungi questo indirizzo tra i Redirect URIs dell'app Spotify.

## Pubblicazione su Vercel

1. <https://vercel.com/new> → importa questo repository da GitHub.
2. Framework preset: **Other**. Nessun comando di build, output directory `./`.
3. Deploy, poi aggiungi l'URL ottenuto ai Redirect URIs su Spotify.

## Sul telefono

- **iPhone**: apri il sito in Safari → Condividi → *Aggiungi alla schermata Home*.
- **Android**: Chrome → ⋮ → *Installa app*.

Se il browser del telefono non riproduce l'audio (su iOS può succedere, e lo schermo bloccato può interrompere la riproduzione web), apri l'app Spotify, tocca l'icona dei dispositivi in Onda e scegli il telefono: Onda la comanda a distanza.

## File

| File | Contenuto |
|---|---|
| `index.html` | Struttura dell'interfaccia |
| `style.css` | Stile (responsive, tema scuro) |
| `app.js` | Login, client API, player, viste, localStorage |
| `sw.js` | Service worker (interfaccia offline, niente cache delle API) |
| `manifest.webmanifest`, `icons/` | PWA |
| `vercel.json` | Header per Vercel |
