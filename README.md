# Bank Management System (Flask + SQLite)

## Run
    pip install -r requirements.txt
    python app.py            # http://127.0.0.1:5000
    # optional: BANK_DEBUG=1 python app.py   (auto-reload while editing)

Put your existing `bank.db` next to `app.py` - it is migrated automatically (nothing is deleted).

## Hero photo
The start page shows the three-employee picture in `static/img/hero.jpg`.
To change it, replace that file (landscape, employees in the lower half; ~1920x1080 looks sharpest). It is picked up automatically.
On phones the whole picture is shown under the heading so all three employees stay visible.

## Front end
`templates/` holds the pages (shared layout in `base.html`, form helpers in `_macros.html`), `static/css/style.css` the styling and `static/js/app.js` small enhancements.
The Content-Security-Policy only allows files from this site, so keep CSS and JavaScript in those files (no inline `<style>`, `style=` or `<script>` blocks).

## Tests
    pip install pytest
    python -m pytest                      # smoke tests on a temporary database
The tests never touch your real `bank.db` or `.secret_key`.

## Environment variables
BANK_SECRET_KEY (else a key is generated in `.secret_key`), BANK_DB (database path), BANK_HTTPS=1 (secure cookies when served over HTTPS), BANK_DEBUG=1.
