# Use an official Python runtime as a parent image
FROM python:3.10.14-slim-bookworm

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Upgrade system packages to patch vulnerabilities and install security updates
RUN apt-get update && \
    apt-get install -y python3 python3-pip netcat-openbsd && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*


RUN apt-get install -y netcat

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

# Expose the port that the application listens on
EXPOSE 80

# Run the application using Uvicorn, listening on all interfaces
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]