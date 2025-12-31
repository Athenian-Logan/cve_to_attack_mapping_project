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
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds

def save_to_json_file(data, filename, mode='a'):
    """Save data to JSON file incrementally."""
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, mode, encoding='utf-8') as json_file:
            if mode == 'a' and os.path.getsize(filename) > 0:
                # Remove the closing bracket if appending to existing file
                json_file.seek(0, os.SEEK_END)
                json_file.seek(json_file.tell() - 1, os.SEEK_SET)
                json_file.truncate()
                json_file.write(',\n')
            
            json.dump(data, json_file, indent=2)
            
            if mode == 'a':
                json_file.write('\n]')
            else:
                json_file.write('\n')
                
        logging.info(f"Saved {len(data)} items to {filename}")
        return True
    except Exception as e:
        logging.error(f"Error saving to file {filename}: {e}")
        return False

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
    """Download all NVD CVE data incrementally."""
    logging.info("Beginning NVD Downloader...")
    
    # Output file
    output_file = "scripts/json_dumps/nvd_json_dump.json"
    
    # Initialize file with empty array
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('[\n')
    
    key_index = 0
    start_index = 0
    total_cves = 0
    batch_size = 100  # Save every 100 vulnerabilities to file
    
    while True:
        # Construct API URL
        nvd_api_url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?resultsPerPage={RESULTS_PER_PAGE}&startIndex={start_index}"
        )
        
        headers = {"apiKey": API_KEYS[key_index]}
        
        logging.info(f"Requesting data: startIndex={start_index}, total so far={total_cves}")
        
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
                break
            
            # Get total results for progress tracking
            total_results = response_json.get("totalResults", 0)
            logging.info(f"Retrieved {len(vulnerabilities)} vulnerabilities. Total in dataset: {total_results}")
            
            # Save current batch to file
            if vulnerabilities:
                save_to_json_file(vulnerabilities, output_file, mode='a')
                total_cves += len(vulnerabilities)
            
            # Update start index for next request
            start_index += RESULTS_PER_PAGE
            
            # Rotate API key for next request
            key_index = (key_index + 1) % len(API_KEYS)
            
            # Be nice to the API - add a small delay between requests
            time.sleep(1)
            
        except KeyboardInterrupt:
            logging.info("Download interrupted by user.")
            break
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            # Rotate API key on error
            key_index = (key_index + 1) % len(API_KEYS)
            time.sleep(RETRY_DELAY)
    
    logging.info(f"Download complete. Total CVEs downloaded: {total_cves}")
    logging.info(f"Data saved to: {output_file}")

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