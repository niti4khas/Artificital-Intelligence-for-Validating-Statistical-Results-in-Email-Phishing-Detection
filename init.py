"""
The init.py file creates a dataset consisting of required email headers information in csv format from the 
collection of .eml files consisting of both phishing and non phishing emails

"""


import pandas as pd
import os
from utilities.utilities import extractFilenamesFromDirectory, parseEmail

data = []
#Columns of the dataset composed of the email headers 
columns = [
  "filename","from","domain","sender_ip","x_sender_ip","return_path","return_path_matched_from","message_id","date","domain_age","spf","dkim","dmarc","received-spf","number_of_hops","max_delay_between_hops",
   "has_been_forwarded","total_forwarded_times","content_type","phishing"
]

# Directory containing .eml files
email_directory = "./data"
file_names = extractFilenamesFromDirectory(email_directory)

#Read the .eml files from the  directory "\data"
for filename in os.listdir(email_directory):
    if filename.endswith('.eml'):
        file_path = os.path.join(email_directory, filename)
        print("in: ",file_path)
        #Parse the .eml files to get the required header informations
        row = parseEmail(file_path)
        data.append(row)

df = pd.DataFrame(data, columns=columns)
#Create and Save the new dataset
csv_file_path = "email_dataset.csv"
df.to_csv(csv_file_path, index=False)
print(f"Dataset saved to {csv_file_path}")
