import os
import csv

folders = ["UK", "USA", "IT", "DE"]

base_path = os.path.dirname(os.path.abspath(__file__))

def merge_files() :
    for country in folders:
        folder_path = os.path.join(base_path, country)
        output_csv = os.path.join(base_path, f"{country}.csv")

        domains = set()

        if not os.path.isdir(folder_path):
            print(f"Cartella non trovata: {folder_path}")
            continue

        for filename in os.listdir(folder_path):
            if filename.lower().endswith(".txt"):
                file_path = os.path.join(folder_path, filename)
                with open(file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        domain = line.strip()
                        if domain:
                            domains.add(domain)

        with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["domain"])
            for domain in sorted(domains):
                writer.writerow([domain])

        print(f"Creato file: {output_csv} ({len(domains)} domini unici)")

if __name__ == "__main__":
    merge_files()