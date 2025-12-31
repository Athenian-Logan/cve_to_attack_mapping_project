import json
import requests
import time
import logging
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# NVD API configuration
API_KEYS = [
    "5f3da5bb-16ed-46b9-a087-ec18e47ec5cb",
    "7261ae13-e9ca-4741-b843-7160cc301a5d", 
    "13e2c275-97f5-4e7a-a800-5f3fdcc0d785",
    "af7a431d-ec71-4f30-868c-d661649d65f4",
    "6061ab83-e57d-4d83-8594-7fe35463afb9"
]

RESULTS_PER_PAGE = 2000
PAGES_PER_FILE = 10  # Save every 10 pages to a new file
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds

def save_batch_to_json(data, batch_num):
    """Save a batch of data to a new JSON file."""
    try:
        output_dir = "scripts/json_dumps/batches"
        os.makedirs(output_dir, exist_ok=True)
        
        filename = f"{output_dir}/nvd_batch_{batch_num:03d}.json"
        
        with open(filename, 'w', encoding='utf-8') as json_file:
            json.dump(data, json_file, indent=2)
                
        logging.info(f"Saved batch {batch_num} with {len(data)} items to {filename}")
        return filename
    except Exception as e:
        logging.error(f"Error saving batch {batch_num}: {e}")
        return None

def make_nvd_request(url, headers, retry_count=0):
    """Make a request to NVD API with retry logic."""
    try:
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            return response
        
        # Rate limiting or other errors
        logging.warning(f"Request failed with status {response.status_code}")
        
        if response.status_code == 403 and retry_count < MAX_RETRIES:
            logging.info(f"Rate limited, retrying in {RETRY_DELAY} seconds...")
            time.sleep(RETRY_DELAY)
            return make_nvd_request(url, headers, retry_count + 1)
            
        response.raise_for_status()
        
    except requests.exceptions.RequestException as e:
        logging.error(f"Request error: {e}")
        if retry_count < MAX_RETRIES:
            logging.info(f"Retrying in {RETRY_DELAY} seconds...")
            time.sleep(RETRY_DELAY)
            return make_nvd_request(url, headers, retry_count + 1)
        raise
    
    return None

def download_nvd_data():
    """Download all NVD CVE data incrementally and save in batches."""
    logging.info("Beginning NVD Downloader with batch saving...")
    
    key_index = 0
    start_index = 0
    total_cves = 0
    batch_num = 0
    current_batch = []
    page_count = 0
    
    while True:
        # Construct API URL
        nvd_api_url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?resultsPerPage={RESULTS_PER_PAGE}&startIndex={start_index}"
        )
        
        headers = {"apiKey": API_KEYS[key_index]}
        
        logging.info(f"Requesting data: startIndex={start_index}, page={page_count + 1}")
        
        try:
            # Make request with retry logic
            response = make_nvd_request(nvd_api_url, headers)
            
            if response is None:
                logging.error("Failed to get response after retries")
                break
                
            response_json = response.json()
            vulnerabilities = response_json.get("vulnerabilities", [])
            
            if not vulnerabilities:
                logging.info("No more vulnerabilities found. Download complete.")
                # Save the last batch if it has data
                if current_batch:
                    save_batch_to_json(current_batch, batch_num)
                break
            
            # Add vulnerabilities to current batch
            current_batch.extend(vulnerabilities)
            page_count += 1
            total_cves += len(vulnerabilities)
            
            # Check if we need to save this batch and start a new one
            if page_count >= PAGES_PER_FILE:
                save_batch_to_json(current_batch, batch_num)
                batch_num += 1
                current_batch = []
                page_count = 0
            
            # Update start index for next request
            start_index += RESULTS_PER_PAGE
            
            # Rotate API key for next request
            key_index = (key_index + 1) % len(API_KEYS)
            
            # Be nice to the API - add a small delay between requests
            time.sleep(1)
            
        except KeyboardInterrupt:
            logging.info("Download interrupted by user.")
            # Save current batch before exiting
            if current_batch:
                save_batch_to_json(current_batch, batch_num)
            break
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            # Rotate API key on error
            key_index = (key_index + 1) % len(API_KEYS)
            time.sleep(RETRY_DELAY)
    
    logging.info(f"Download complete. Total CVEs downloaded: {total_cves}")
    logging.info(f"Data saved in batches to: scripts/json_dumps/batches/")

def main():
    """Main function with error handling."""
    try:
        download_nvd_data()
    except KeyboardInterrupt:
        logging.info("Script terminated by user.")
    except Exception as e:
        logging.error(f"Script failed with error: {e}")
        raise

if __name__ == "__main__":
    main()