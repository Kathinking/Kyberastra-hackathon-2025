import pandas as pd

# Define the input and output filenames
input_file = 'extracted_features.csv'
output_file = 'extracted_features_no_label.csv'

# 1. Read the CSV file into a pandas DataFrame
try:
    df = pd.read_csv(input_file)

    # 2. Drop (delete) the 'label' column
    # The axis=1 specifies that we are targeting a column.
    df = df.drop('Label', axis=1)

    # 3. Save the updated DataFrame to a new CSV file
    # index=False prevents pandas from writing a new index column
    df.to_csv(output_file, index=False)

    print(f"Successfully removed the 'label' column and saved the result to '{output_file}'")

except FileNotFoundError:
    print(f"Error: The file '{input_file}' was not found.")
except KeyError:
    print(f"Error: The column 'label' was not found in '{input_file}'.")