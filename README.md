# CVE to  Mitre ATT&CK Mapping Project

## Project Pipelines

### **Unsupervised (SMET)**

1. Run NVD Data Downloader (scripts/nvd_downloader.py)
2. Extract Mitre Mappings from (mitre_cve_to_attack_mappings.csv) with (extract_mitre_mappings.py)
3. Construct Dataset from Mitre Mappings (scripts/SMET/construct_dataset_from_mitre_mappings.py)

***Step 3 includes Data-Pre-processing found in scripts/SMET/preprocess.py***

4. Run (Unsupervised/SMET/main/run.py) to execute SMET Mapping.


### Supervised (secRoBERTa)

1. Run NVD Data Downloader (scripts/nvd_downloader.py)
2. Run Dataset Feature Expansion Script (to construct variant datasets) with (scripts/supervised/construct_enriched_to_tactic_dataset.py)

***Step 2 includes Data-Pre-processing found in scripts/supervised/preprocess.py which in turn includes the exploratory CAPEC Web Scraping and Processing.***

3. If running Best Dataset, further enhance dataset with EPSS by running (scripts/supervised/download_epss_info.py) which auto-enriches a given dataset with the downloaded EPSS.
4. Now split your dataset into the 80/20 training and val split, using (scripts/supervised/split_full_dataset.py)
5. Now, when running the modified supervised script, select your variant modified code, the best run was executed using (Supervised/secroberta-to-tactic-epss-post-hyperparam-tuning.py)
6. With your console logs, you can optionally visualise results using (scripts/compare_supervised_results.py) or (scripts/compare_many_supervised_results.py)


***N.B. The script used for Hyper-parameter fine-tuning is also found in (Supervised/hyperparameter_fine_tuning.py)***


**SMET Code taken from paper:** 

Zhang, X., Liu, Y., & Li, J. (2023). SMET: Semantic Mapping of CVE to ATT&CK and its Application to Cybersecurity. NIST Special Publication. [https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=936761](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=936761)

**SecRoBERTa (Supervised Code) taken from paper:**

Mihaček, P., et al. (2024). Automated Mapping of Common Vulnerabilities and Exposures to MITRE ATT&CK Tactics. Information, 15(4), 214. [https://www.mdpi.com/2078-2489/15/4/214](https://www.mdpi.com/2078-2489/15/4/214)
