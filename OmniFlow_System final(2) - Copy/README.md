# OmniFlow backend (Flask)

## Quick start
1) Create venv (optional)
```bash
python -m venv .venv
. .venv/Scripts/activate  # Windows
```
2) Install deps
```bash
pip install -r requirements.txt
```
3) Run server
```bash
python app.py
```
4) Open http://localhost:5000/login and sign in.

## Login
- Email: admin@omniflow.test
- Password: admin123

## API overview
- `GET /api/home/stats` – numbers for home cards
- `GET /api/orders` (+ search/status/client_id), `POST /api/orders`, `GET/PUT/DELETE /api/orders/<id>`, `GET /api/orders/recent`
- `GET/POST /api/clients`, `GET/PUT/DELETE /api/clients/<id>`
- `GET/POST /api/inventory`, `GET/PUT/DELETE /api/inventory/<id>`
- `GET /api/production/board`
- `GET /api/dashboard/kpis|revenue|order-status|throughput|top-products`
- `GET /api/reports`, `GET /api/reports/forecast`
- `GET /api/activity`, `GET /api/me`

Activity feed: all add/update/delete actions for orders, clients, and inventory are logged automatically.

Data is stored in `data.json`. Edits through the API persist automatically.
