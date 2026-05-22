# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy requirements file (we will create a mock one or rely on standard packages if missing, 
# but assuming requirements.txt exists or we can just install directly for this prototype)
# We will just copy everything first.
COPY . /app

# Install dependencies directly based on imports used in app.py
RUN pip install --no-cache-dir flask gunicorn scikit-learn numpy pandas requests maxminddb python-telegram-bot

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variable
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Initialize the database before running
RUN python3 init_db.py

# Run gunicorn when the container launches
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "3", "app:app"]
