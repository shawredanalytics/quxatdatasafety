# QuXAT Data Safety Application

Streamlit MVP for healthcare organizations to:
- Perform a basic ISO 27001 self-assessment
- Assess ransomware risk exposure
- Generate simple PDF compliance reports

## 1. Prerequisites

- Python 3.11
- Git

## 2. Setup Instructions

1. Clone the repository.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. (Optional) Create a `.env` file based on `.env.example`.

## 3. Run Locally

```bash
streamlit run app.py
```

Open the URL shown in the terminal (typically `http://localhost:8501`) in your browser.

## 4. Deploy on Streamlit Cloud

1. Push this project to a GitHub repository.
2. Go to Streamlit Community Cloud and create a new app.
3. Select your GitHub repo and choose `app.py` as the entry point.
4. In advanced settings, add environment variables defined in `.env.example` as needed.
5. Deploy the app.

## 5. Push to GitHub

From the root of your project (containing the `healthsecure_mvp` folder):

```bash
git init
git add .
git commit -m "Add healthsecure_mvp Streamlit app"
git branch -M main
git remote add origin <your-github-repo-url>
git push -u origin main
```

## 6. Default Admin Login

- Username and password can be configured via environment variables in `.env`.
- If no environment variables are set, a default admin account is created on first run as described in `app.py`.
