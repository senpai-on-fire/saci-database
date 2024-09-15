# cpv-database
A database of CPVs described using SACI

# NL2ASP

NL2ASP is a Python program that leverages OpenAI's API to generate vulnerability assessments for systems. The project consists of two main scripts: `generate_vulnerability_files.py` and `run_vulnerability_assessment.py`.

## Setup Instructions

Follow these steps to set up and run the program:

### 1. Clone the Repository

If you haven't already, clone the repository to your local machine:

```bash
git clone https://github.com/yourusername/saci_db.git
cd saci_db/nl2asp
```

### 2. Configure Environment Variables
Before running the program, you need to configure your OpenAI API key. You can do this by copying the .env.example file and creating a new .env file:

```bash
cd saci_db/nl2asp/
cp .env.example .env
```
Then, open the .env file and add your OpenAI API key:

```bash
OPENAI_API_KEY=your_openai_api_key_here
```

### 3. Install Required Packages
Next, install the required Python packages specified in the requirements.txt file:

```bash
pip3 install -r requirements.txt
```
This will install the necessary dependencies, including OpenAI and python-dotenv.

### 4. Running the Program
The program consists of two scripts that should be run in sequence:

Step 1: Generate Vulnerability Files
Run the `generate_vulnerability_files.py` script to generate the necessary files for the vulnerability assessment:

```bash
python3 generate_vulnerability_files.py
```
This will use the OpenAI API to generate the required files based on the input data.

Step 2: Run the Vulnerability Assessment
Once the vulnerability files have been generated, you can run the assessment using the `run_vulnerability_assessment.py` script:

```bash
python3 run_vulnerability_assessment.py
```
This will process the files and provide the results of the vulnerability assessment.
