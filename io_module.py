import pandas as pd
import geopandas as gpd
from pathlib import Path

def read(file_path, config):
    path = Path(file_path)
    suffix = path.suffix.lower()
    name = path.name

    if suffix == ".csv":
        with open(path, "rb") as f:
            content = f.read()
        return name, content

    elif suffix in [".geojson", ".json", ".kml"]:
        with open(path, "rb") as f:
            content = f.read()
        return name, content

    else:
        raise ValueError(f"Unsupported file format: {suffix}")
