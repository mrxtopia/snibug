import json
import csv
import os
from typing import List

class ResultSaver:
    def __init__(self, output_dir: str = "results"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def save_json(self, results: List[dict], filename: str = "scan_results.json"):
        path = os.path.join(self.output_dir, filename)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4)
        return path

    def save_csv(self, results: List[dict], filename: str = "scan_results.csv"):
        path = os.path.join(self.output_dir, filename)
        if not results:
            return path
            
        keys = results[0].keys()
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(results)
        return path

    def save_txt(self, results: List[dict], filename: str = "working_hosts.txt"):
        path = os.path.join(self.output_dir, filename)
        with open(path, 'w', encoding='utf-8') as f:
            for res in results:
                if res.get('status') == 'WORKING':
                    f.write(f"{res.get('host')}:{res.get('port', 443)}\n")
        return path
