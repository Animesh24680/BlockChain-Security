# 🛡️ PS-HK17: AI-Driven Smart Contract Risk Scoring

AI-powered pre-deployment security platform for smart contracts.

## 🚀 Quick Start
```bash
# Install dependencies
pip install -r requirements.txt
solc-select install 0.8.20 && solc-select use 0.8.20

# Train initial model
python -m backend.ml.train

# Start backend
uvicorn backend.main:app --port 8000 &

# Start frontend
streamlit run frontend/app.py
## 🐬 Docker Compose (Recommended)
The easiest way to run the entire stack:

```bash
docker-compose up --build -d
```
- Access Frontend: [http://localhost:8501](http://localhost:8501)
- Access Backend API: [http://localhost:8000](http://localhost:8000)

## 🐳 Manual Docker Deployment
If you prefer running containers individually:

```bash
# Build images
docker build -t ps-hk17-backend -f Dockerfile.backend .
docker build -t ps-hk17-frontend -f Dockerfile.frontend .

# Run Backend
docker run -d -p 8000:8000 --name backend ps-hk17-backend

# Run Frontend (point to the backend container or host IP)
docker run -d -p 8501:8501 -e BACKEND_URL="http://localhost:8000" --name frontend ps-hk17-frontend
```

## 🚂 Deploy to Railway (Suitable for Python/AI)
Since this project requires a Python backend with Slither, **Railway** is the best choice. It will automatically detect our `docker-compose.yml`.

1.  **Push this code to GitHub.**
2.  Go to [Railway.app](https://railway.app/).
3.  Click **"New Project"** -> **"Deploy from GitHub repo"**.
4.  Railway will see the `docker-compose.yml` and start both the Backend and Frontend.
5.  **Important**: In the Railway settings for the `frontend` service, ensure the `BACKEND_URL` environment variable is set to the public URL of your `backend` service.

## ☁️ Other Cloud Options
- **Render**: Create two "Web Services" (one for Backend, one for Frontend) and use the `Dockerfile`s provided.
- **Google Cloud Run**: Use the `gcloud run deploy` commands mentioned above.
