import pandas as pd
import numpy as np

# Load dataset
data = pd.read_csv("../../dataset/fake_job_postings.csv")

# Show first 5 rows
print(data.head())

# Show dataset information
print(data.info())

# Show number of fake vs real jobs
print(data['fraudulent'].value_counts())