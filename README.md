# Offline Classroom Attendance — v2.1

Local Flask + SQLite server with in-browser face recognition (face-api.js). Runs entirely on the phone
(Termux + Chrome), no internet needed after setup. Designed for one class of 30–50 students.

**Still a prototype, not a certified biometric product.** Read *Limitations* before using it for anything official.

## What's new in v2.1

| Feature | Details |
|---|---|
| **Calibration tab** | Enrol a face *while* watching live readouts: camera resolution, face size (px and % of frame), detection score, estimated distance, nearest student, match distance `d`, and the verdict. An overlay shows the smallest accepted face (white dashed box) and the expected face size at 1 m (cyan dotted box). Nothing is recorded as attendance on this tab. |
| **Detection up to 1 m** | Camera is requested at 720p; the detector input is larger (default 512, Settings → *Detection quality*); the smallest accepted face is 8% of the frame width (Settings), which allows scanning out to roughly 1.3 m. Enrolment now takes **7 samples**: three near (~50 cm), then 75 cm and three at ~1 m, so the face is learned at the range it is scanned. |
| **Accuracy by distance** | The Calibration tab keeps a table of readings, average `d` and match rate for ≤60 cm, 60–85 cm, 85–110 cm and >110 cm, so you can confirm accuracy at 1 m before relying on it. |
| **Excel export** | Daily tab → **Download Excel** and Monthly tab → **Download Excel summary**. The monthly workbook has three sheets: *Monthly Summary* (present / late / excused / absent / attendance %, class total), *Day by Day* (P/L/E/A grid per school day) and *Totals per Day*. Same numbers and rules as the on-screen report. |

## What changed from v1

| Area | v1 | v2 |
|---|---|---|
| Access control | None: any local app could read/delete everything | Admin PIN (PBKDF2), 10-min idle timeout, lockout after 5 bad PINs, CSRF token, Host/Origin checks, CSP and security headers. The kiosk (Live tab) needs no login but can only mark attendance |
| Biometric exposure | `/api/descriptors` sent **every** face template to the browser every 1.2 s | Matching is done server-side; templates never leave the server |
| Accuracy | 1 enrolment frame, 1 match frame | 5 pose-varied samples, consistency check, duplicate-face check, N-frame confirmation, ambiguity margin (two similar students ⇒ no auto-mark) |
| Speed / battery | Full descriptor + full DB download on every scan | Cheap detection loop; descriptor computed only when needed; roster cached in memory |
| Anti-spoofing | None | Optional blink check (stops static photos only; not video replay) |
| Rules | First scan = present | Class start + late rule, excused absences, holidays and school-day calendar |
| Reports | "Days present" only | Present / Late / Excused / Absent and a real attendance % against school days |
| Corrections | Manual mark only for absent students | Mark present/excused, correct, or remove any record; all logged |
| Auditability | None | Audit log of logins, edits, deletions, setting changes, backups |
| Data hygiene | Hard-delete only; CSV open to formula injection | Deactivate/edit/re-capture; CSV formula-injection neutralised; retention purge; online backup |
| Database | Foreign keys off, no indexes | Foreign keys on, WAL, date index, versioned additive migration |

## Setup (Termux)

```sh
pkg update && pkg upgrade
pkg install python
cd ~/attendance            # the unzipped project
python -m pip install -r requirements.txt   # Flask + openpyxl (Excel export)
./start.sh                 # sets TZ=Asia/Manila (edit start.sh for another zone)
```

Open **http://127.0.0.1:8765** in Chrome on the same phone (use that exact address; `localhost` also works).
The server binds to 127.0.0.1 only. Do not change it to 0.0.0.0.

`static/face-api.min.js` and `static/models/` are already included. If you rebuild from scratch, see the
download commands in the v1 README and verify file provenance.

### First run
1. Tap **Set admin PIN** (6+ characters). If you forget it: `python app.py --set-pin` in Termux.
2. Live tab → **Start camera**, confirm the picture is from the USB webcam (use the camera dropdown; the choice is remembered).
3. Calibration tab → enter number and name → **Capture 7 samples**. Follow the prompts: three poses at about 50 cm, then step back to about 75 cm and to about 1 meter. (The Students tab can enrol too, without the live readouts.)
4. Settings → set class start time, late grace period, school days, holidays.
5. Calibrate before relying on it (below), using the **Calibration** tab.

### Upgrading from v1
1. **Stop the app and copy `attendance.db` somewhere safe.**
2. Put your old `attendance.db` in this folder. It is migrated automatically on start: existing students and attendance are kept (old records become *present*).
3. Migrated students have only 1 sample. Use **Re-capture** on each to get the accuracy benefit.

## Calibration (do this once, ~30 minutes)
1. Open **Calibration**, start the camera, measure 1 m from the lens with a tape, stand there, and tap **Set 1 m reference**. Distances are then calibrated for your camera (otherwise they are ±20% estimates).
2. Enrol 5–10 consenting volunteers on this tab. After each enrolment the tab tracks that student: stand at 50 cm, 75 cm and 1 m for a few seconds each and check the *Accuracy by distance* table (match rate should be high and average `d` well under the threshold at every distance up to 1 m).
3. Test each volunteer in the real classroom lighting, plus a few non-enrolled people (they should read *Not recognised*).
4. Choose a threshold above the genuine distances and well below the impostor distances (default 0.48). If look-alikes are common, raise *ambiguity margin*. If students are missed, improve lighting before loosening the threshold.

## Daily use
- Mount the phone/webcam at face height, facing the door, away from backlight. Keep the screen on (the app requests a wake lock).
- A teacher should supervise. Anyone not recognised is marked manually in **Daily → Present / Excused**.
- Export CSV or Excel from the Daily/Monthly tabs. Download a backup weekly (Settings → Download backup) and store it encrypted.

## Security notes
- Admin pages and all report/CSV/backup endpoints require login. The kiosk can only submit a face for matching.
- The session cookie is HttpOnly + SameSite=Strict; the signing key lives in `.secret_key` (mode 600). Do not copy it with backups.
- The backup file contains biometric templates. Treat it as sensitive.
- CSP allows `'unsafe-eval'` for scripts because the bundled TensorFlow.js in face-api.js needs it. Only your own files can load.

## Limitations
- No true liveness detection. The blink check deters photo holding, not a recorded video.
- face-api.js accuracy varies by lighting, camera, age group and skin tone. Validate on your own students and keep a manual fallback.
- On phones without WebGL the model runs on CPU and scanning can be slow; Chrome on a mid-range Android is usually fine. If scanning feels slow, lower *Detection quality* to 416 (range drops to about 80 cm).
- Range depends on the camera. A 1 m face is about 140 px wide on a 720p webcam but only about 70 px on a 640×480 one, which is too small for reliable matching. Use a 720p (or better) webcam, face the light, and avoid backlight.
- Distance readouts assume an average adult face and are only a guide (±10–20%).
- Chrome may not expose a USB webcam on every Android build. Test before committing.
- Record only as much as you need. Agree retention, consent and a non-biometric alternative with the school before enrolling real students. Use **Settings → Purge old records** for retention.

## Tests

```sh
python -m unittest discover -s tests -v
```
Covers auth/CSRF/host checks, enrolment validation, matching/ambiguity/late/liveness rules, calendar-aware reports, CSV and Excel export (content and formula-injection safety), the calibration probe, long-range settings, backup, purge and v1→v2 migration. The Excel tests need `openpyxl`.

## Files
`app.py` server • `templates/index.html` • `static/app.js`, `static/app.css` • `static/face-api.min.js`, `static/models/` • `tests/` • `start.sh`
