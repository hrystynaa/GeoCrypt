import pandas as pd
import geopandas as gpd
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

def read_and_validate(file_path, config):
    """
    Зчитує вхідний файл (GeoJSON, KML або CSV), перевіряє правильність і повертає пару (ім'я_файлу, байти_даних).
    Для CSV перевіряє наявність стовпців широта/довгота та числовий формат.
    Для GeoJSON перевіряє CRS і приводить до WGS84, потім генерує JSON-рядок.
    Для KML читає за допомогою GeoPandas для перевірки, але повертає оригінальний вміст.
    """
    path = Path(file_path)
    suffix = path.suffix.lower()
    name = path.name
    if suffix == ".csv":
        # Читання CSV і валідація колонок
        lat_col = config.get("csv", {}).get("lat", "Latitude")
        lon_col = config.get("csv", {}).get("lon", "Longitude")
        try:
            df = pd.read_csv(path)
        except Exception as e:
            logger.error(f"Не вдалося зчитати CSV-файл: {e}")
            raise
        if lat_col not in df.columns or lon_col not in df.columns:
            raise ValueError(f"CSV має не вірні назви колонок: очікуються '{lat_col}' і '{lon_col}'")
        # Переконуємося, що координати числові
        try:
            pd.to_numeric(df[lat_col])
            pd.to_numeric(df[lon_col])
        except Exception as e:
            raise ValueError(f"Колонки '{lat_col}' або '{lon_col}' мають нечислові значення: {e}")
        # Успішно валідовано; читаємо байти оригінального файлу
        try:
            with open(path, "rb") as f:
                content = f.read()
        except Exception as e:
            logger.error(f"Не вдалося відкрити CSV для читання байтів: {e}")
            raise
        logger.debug(f"CSV-файл '{name}' валідовано та прочитано")
        return name, content

    elif suffix in [".geojson", ".json"]:
        # GeoJSON: читаємо в GeoDataFrame
        try:
            gdf = gpd.read_file(path)
        except Exception as e:
            logger.error(f"Не вдалося зчитати GeoJSON: {e}")
            raise
        # Перевіряємо CRS, конвертуємо у WGS84
        if gdf.crs is not None and gdf.crs.to_epsg() != 4326:
            gdf = gdf.to_crs(epsg=4326)
            logger.debug("Конвертація GeoJSON до WGS84 (EPSG:4326)")
        # Генеруємо JSON
        try:
            json_str = gdf.to_json()
        except Exception as e:
            logger.error(f"Не вдалося згенерувати JSON з GeoDataFrame: {e}")
            raise
        content = json_str.encode('utf-8')
        # Встановлюємо ім'я з розширенням .geojson
        if not name.lower().endswith(".geojson"):
            name = path.stem + ".geojson"
        logger.debug(f"GeoJSON-файл '{name}' зчитано")
        return name, content

    elif suffix == ".kml":
        # KML: перевірка через GeoPandas, але контент не міняємо
        try:
            gdf = gpd.read_file(path, driver='KML')
        except Exception:
            try:
                gdf = gpd.read_file(path)  # спроба без явного драйвера
            except Exception as e:
                logger.error(f"Не вдалося зчитати KML: {e}")
                raise

        try:
            with open(path, "rb") as f:
                content = f.read()
        except Exception as e:
            logger.error(f"Не вдалося відкрити KML для читання: {e}")
            raise
        logger.debug(f"KML-файл '{name}' зчитано (без перетворення)")
        return name, content

    else:
        raise ValueError(f"Непідтримуваний формат файлу: {suffix}")

