# Use the official Python image as a parent image
FROM python:3.8

# Set the working directory to /app
WORKDIR /app

# Copy the contents of the current directory to /app in the container
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 5001 for the Flask app
EXPOSE 5001

# Run the command to start the Flask app
CMD ["python3", "main.py"]