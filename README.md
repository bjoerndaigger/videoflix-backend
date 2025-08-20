# Project Setup

This project is a Django-based application with Docker support. Follow the instructions below to set up the project locally.

## 1. Clone the Repository

```bash
# Clone the repository and navigate to the project folder
git clone <REPO-URL>
cd <project>
```

## 2. Create a virtual environment and install dependencies

### On macOS / Linux:

```bash
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

### On Windows:

```shell
python -m venv env
env/Scripts/activate
pip install -r requirements.txt
```

## 3. Environment Variables

Copy the template `.env` file and update it with your own values.

```bash
cp .env.template .env
```

### Example `.env` configuration:

```env
DJANGO_SUPERUSER_USERNAME=admin
DJANGO_SUPERUSER_PASSWORD=adminpassword
DJANGO_SUPERUSER_EMAIL=admin@example.com

SECRET_KEY='django-insecure-lp6h18zq4@z30symy*oz)+hp^uoti48r_ix^qc-m@&yfxd7&hn'
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
CSRF_TRUSTED_ORIGINS=http://localhost:4200,http://127.0.0.1:4200

DB_NAME=your_database_name
DB_USER=your_database_user
DB_PASSWORD=your_database_password
DB_HOST=db
DB_PORT=5432

REDIS_HOST=redis
REDIS_LOCATION=redis://redis:6379/1
REDIS_PORT=6379
REDIS_DB=0

EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_HOST_USER=your_email_user
EMAIL_HOST_PASSWORD=your_email_user_password
EMAIL_USE_TLS=True
EMAIL_USE_SSL=False
DEFAULT_FROM_EMAIL=default_from_email
```

> Make sure to replace all placeholder values with your own secure credentials.

## 4. Running the Project with Docker

Make the backend entrypoint script executable and start Docker:

```bash
chmod +x backend.entrypoint.sh # Optional for Mac users
docker-compose up --build
```

This setup will create and start all necessary services (PostgreSQL, Redis, Django app) in Docker containers. You can now access the application on `http://localhost:8000`.
