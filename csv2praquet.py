import pandas as pd
import sys

if __name__ == "__main__":
    if len(sys.argv) != 1:
        print("Usage: python csv2parquet.py <input_csv_file> <output_parquet_file>")
        sys.exit(1)

    input_csv_file = "extracted_features.csv"
    output_parquet_file = "output.parquet"
    

    try:
        # Read the CSV file
        df = pd.read_csv(input_csv_file)

        # Convert to Parquet
        df.to_parquet(output_parquet_file, index=False)

        print(f"Successfully converted '{input_csv_file}' to '{output_parquet_file}'")

    except FileNotFoundError:
        print(f"Error: Input CSV file '{input_csv_file}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)
