# Offline map data

Used by the FIREWALL tab of `webui/static/js/app.js`; the map draws itself and loads nothing from the network.

- `world.json`: the land outline, built on 2026-11-16 by `scripts/build-worldmap.py` from Natural Earth's 110m land mask `ne_110m_land.geojson`, version 5.1.2 (https://github.com/nvkelso/natural-earth-vector/blob/v5.1.2/geojson/ne_110m_land.geojson, SHA-256 `9e0729ee253ca7d7a5c4ae9395fb1902264c5377c52e224d13dd85010e2835d9`). Licence of the source: public domain (https://www.naturalearthdata.com/about/terms-of-use/). Simplified with Douglas-Peucker to 0.4°, rings under 1.5° of perimeter dropped, rounded to tenths of a degree. The source is not kept; to refresh, download it and run `python3 scripts/build-worldmap.py <path to ne_110m_land.geojson>`.
