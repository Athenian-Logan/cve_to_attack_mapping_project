# from main.SMET import map_text
from scripts.SMET.preprocess import *
import pandas as pd

# Open and read CVEs from given csv file. Hold as In Memory dictionary with all enriched info.

data_file = "SMET/main/CVE_annotated_dataset.xlsx"
data = pd.read_excel(data_file)

cve_data = data.to_dict(orient='records')
print(cve_data)

# For each CVE, map enriched data feed and then only description.
# From this, we will compare effectiveness of my approach and make graphs.
