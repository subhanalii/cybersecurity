# vigilanteye/siem/Dockerfile

# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies needed to compile complex Python libraries (like numpy/scikit-learn)
RUN apt-get update && \
    apt-get install -y build-essential gcc python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy the requirements file first 
COPY requirements.txt /app/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . /app

# Make port 5000 available 
EXPOSE 5000

# Command to run app.py when the container launches
CMD ["python", "app.py"]